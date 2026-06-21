//! src/blockchain/blockchain_001_validation.rs

use crate::blockchain::block_001_metadata::BlockMetadata;
use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::genesis_001_block::GenesisBlock;
use crate::blockchain::halving_schedule::RewardHalving;
use crate::blockchain::transaction_001_tx::Transaction;
use crate::blockchain::transaction_003_tx_reward::RewardTx;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use crate::blockchain::validatorstate::ValidatorState;

use crate::consensus::por_002_puzzle_engine::PorPuzzleEngine;
use crate::consensus::por_005_time_management::TimeManager;
use crate::consensus::por_006_committee_eligibility::CommitteeEligibility;
use crate::consensus::por_007_leader_schedule::LeaderSchedule;

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::alpha_003_detection_system::DetectionSystem;
use crate::utility::helper::canon_wallet_id_checked;

use fips204::ml_dsa_65;
use fips204::ml_dsa_65::PublicKey as VerifyingKey;
use hex;

/// Collection of static validation helpers.
pub struct BlockchainValidation;

pub struct FullBlockValidationContext<'a> {
    pub verifying_key: &'a VerifyingKey,
    pub previous_timestamp: Option<u64>,
    pub detection: &'a DetectionSystem,
    pub validator_state: &'a ValidatorState,
    pub committee_eligibility: &'a CommitteeEligibility,
    pub tm: &'a TimeManager,
}

impl BlockchainValidation {
    // ─────────────────────────────────────────────────────────────
    // 1) Genesis-level checks
    // ─────────────────────────────────────────────────────────────

    /// Ensure the genesis block’s prev_hash is all-zero and the Merkle root
    /// is non-zero and not all-0xFF.
    pub fn validate_genesis_block(genesis_block: &GenesisBlock) -> Result<(), ErrorDetection> {
        let zeros64 = [0u8; 64];
        let ff64 = [0xFFu8; 64];

        if genesis_block.prev_hash != zeros64 {
            return Err(ErrorDetection::ValidationError {
                message: "Invalid genesis block: prev_hash must be all zeros".into(),
                tx_id: None,
            });
        }
        if genesis_block.prev_hash == ff64 {
            return Err(ErrorDetection::ValidationError {
                message: "Invalid genesis block: prev_hash cannot be all 0xFF".into(),
                tx_id: None,
            });
        }
        if genesis_block.merkle_root == zeros64 {
            return Err(ErrorDetection::ValidationError {
                message: "Invalid genesis block: merkle_root must not be zero".into(),
                tx_id: None,
            });
        }
        if genesis_block.merkle_root == ff64 {
            return Err(ErrorDetection::ValidationError {
                message: "Invalid genesis block: merkle_root cannot be all 0xFF".into(),
                tx_id: None,
            });
        }
        println!("✅ Genesis block header is valid.");
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // 2) Transaction-level checks
    // ─────────────────────────────────────────────────────────────

    pub fn validate_transaction(tx: &Transaction) -> Result<(), ErrorDetection> {
        tx.validate()?;

        if tx.amount > GlobalConfiguration::MAX_TX_AMOUNT {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Transaction amount {} exceeds the allowed maximum {}",
                    tx.amount,
                    GlobalConfiguration::MAX_TX_AMOUNT
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    /// Validate + finalize a `TransactionBatch`, returning its `BlockMetadata`.
    /// The caller must supply the shared `DetectionSystem`
    /// double-spend checks before signing.
    pub fn validate_transaction_batch(
        batch: &mut TransactionBatch,
        signing_key: &ml_dsa_65::PrivateKey,
        previous_hash: [u8; 64],
        detection: &DetectionSystem,
    ) -> Result<BlockMetadata, ErrorDetection> {
        for kind in &batch.transactions {
            match kind {
                TxKind::Transfer(tx) => Self::validate_transaction(tx)?,
                _ => kind.validate()?,
            }
        }

        let tx_ids = batch
            .transactions
            .iter()
            .filter_map(|kind| match kind {
                TxKind::Transfer(tx) => Some(tx.id()),
                _ => None,
            })
            .collect::<Result<Vec<_>, _>>()?;
        detection.detect_double_spend(tx_ids)?;

        batch.finalize_block(signing_key, previous_hash)
    }

    /// Validate a single `RewardTx` (coinbase transfer).
    pub fn validate_reward_transaction(reward_tx: &RewardTx) -> Result<(), ErrorDetection> {
        reward_tx.validate()?;
        tracing::debug!("✅ RewardTx OK → {} micro-AOS", reward_tx.amount);
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // 3) BlockMetadata checks
    // ─────────────────────────────────────────────────────────────
    pub fn validate_block_metadata(
        metadata: &BlockMetadata,
        _detection: &DetectionSystem,
    ) -> Result<(), ErrorDetection> {
        if metadata.index == 0 && metadata.previous_hash != [0u8; 64] {
            return Err(ErrorDetection::ValidationError {
                message: "Genesis metadata previous_hash must be zero".into(),
                tx_id: None,
            });
        }
        if metadata.index > 0 && metadata.previous_hash == [0u8; 64] {
            return Err(ErrorDetection::ValidationError {
                message: "Non-genesis metadata previous_hash cannot be zero".into(),
                tx_id: None,
            });
        }

        let zeros64 = [0u8; 64];
        let ff64 = [0xFFu8; 64];
        if metadata.merkle_root == zeros64 || metadata.merkle_root == ff64 {
            return Err(ErrorDetection::ValidationError {
                message: "Metadata merkle_root cannot be zero or all 0xFF".into(),
                tx_id: None,
            });
        }
        if metadata.previous_hash == ff64 {
            return Err(ErrorDetection::ValidationError {
                message: "Metadata previous_hash cannot be all 0xFF".into(),
                tx_id: None,
            });
        }

        if metadata.guardian_signature.iter().all(|&b| b == 0) {
            return Err(ErrorDetection::ValidationError {
                message: "Metadata guardian signature is zero".into(),
                tx_id: None,
            });
        }
        if metadata.guardian_signature.iter().all(|&b| b == 0xFF) {
            return Err(ErrorDetection::ValidationError {
                message: "Metadata guardian signature is all 0xFF".into(),
                tx_id: None,
            });
        }

        if metadata.size < 64 || metadata.size > GlobalConfiguration::MAX_BLOCK_SIZE {
            return Err(ErrorDetection::ValidationError {
                message: format!("Metadata size {} out of plausible bounds", metadata.size),
                tx_id: None,
            });
        }

        if metadata.index > 0 && metadata.merkle_root == metadata.previous_hash {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Metadata: merkle_root == previous_hash (index {})",
                    metadata.index
                ),
                tx_id: None,
            });
        }

        if metadata.timestamp < 946684800 {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Metadata timestamp out of range (too old): {}",
                    metadata.timestamp
                ),
                tx_id: None,
            });
        }

        // Structural puzzle-proof checks at the metadata layer.
        if metadata.index == 0 {
            if metadata.puzzle_proof.is_some() {
                return Err(ErrorDetection::ValidationError {
                    message: "Genesis metadata must not include puzzle_proof".into(),
                    tx_id: None,
                });
            }
        } else if let Some(proof) = metadata.puzzle_proof.as_ref() {
            proof.validate_structural()?;

            if proof.height != metadata.index {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Metadata puzzle_proof.height {} does not match metadata.index {}",
                        proof.height, metadata.index
                    ),
                    tx_id: None,
                });
            }

            if proof.prev_block_hash != metadata.previous_hash {
                return Err(ErrorDetection::ValidationError {
                    message:
                        "Metadata puzzle_proof.prev_block_hash does not match metadata.previous_hash"
                            .into(),
                    tx_id: None,
                });
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // 4) Full block validation (canonical committee + canonical leader schedule)
    // ─────────────────────────────────────────────────────────────
    pub fn validate_full_block(
        block: &Block,
        batch: &TransactionBatch,
        ctx: &FullBlockValidationContext<'_>,
    ) -> Result<(), ErrorDetection> {
        let height = block.metadata.index;

        // Structural metadata checks first.
        Self::validate_block_metadata(&block.metadata, ctx.detection)?;

        // Deterministic anti-timewarp gate.
        Self::validate_block_timestamp_deterministic(
            &block.metadata,
            ctx.previous_timestamp,
            ctx.tm,
        )?;

        // Non-genesis blocks must never reference a zero previous hash.
        if height > 0 && block.metadata.previous_hash == [0u8; 64] {
            return Err(ErrorDetection::ValidationError {
                message: format!("Non-genesis block #{} contains zero previous_hash", height),
                tx_id: None,
            });
        }

        let miner_wallet_canon = canon_wallet_id_checked(block.miner_wallet()).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!(
                    "Block miner wallet is not canonical/valid for proposer validation: {:?}",
                    e
                ),
                tx_id: None,
            }
        })?;

        // Canonical active-set sanity check:
        // this MUST NOT use runtime filtering.
        let activation_delay_blocks = ctx.tm.proposer_delay_blocks();
        let canonical_active: Vec<String> =
            LeaderSchedule::canonical_validators_for_height(ctx.validator_state, ctx.tm, height)?;

        let miner_in_canonical_set = canonical_active
            .iter()
            .any(|w| w.eq_ignore_ascii_case(&miner_wallet_canon));

        if !miner_in_canonical_set {
            let join_h_opt = ctx.validator_state.join_height(&miner_wallet_canon);

            let eligible_at_opt = join_h_opt.map(|join_h| {
                if join_h == 0 {
                    0
                } else {
                    join_h.saturating_add(activation_delay_blocks)
                }
            });

            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Rogue block: proposer '{}' is not in canonical validator set at height {}. \
                     join_height={:?} → eligible_at={:?} (proposer_delay_blocks={}).",
                    miner_wallet_canon,
                    height,
                    join_h_opt,
                    eligible_at_opt,
                    activation_delay_blocks
                ),
                tx_id: Some(miner_wallet_canon),
            });
        }

        // Runtime/local committee-eligibility is intentionally ignored by the
        // patched LeaderSchedule consensus path.
        let leader_trace = LeaderSchedule::validate_proposer_from_block_timestamp(
            ctx.validator_state,
            ctx.committee_eligibility,
            ctx.tm,
            block.metadata.previous_hash,
            block.metadata.index,
            block.metadata.timestamp,
            &miner_wallet_canon,
        )?;

        let leader_trace_fp = LeaderSchedule::trace_fingerprint(&leader_trace);

        tracing::debug!(
            "[VALIDATION][LEADER] block #{} proposer='{}' round={} committee_len={} committee_hash={} parent_hash={} trace_fp={}",
            block.metadata.index,
            miner_wallet_canon,
            leader_trace.decision.round,
            leader_trace.decision.committee_len,
            hex::encode(leader_trace.snapshot.committee_hash),
            hex::encode(leader_trace.snapshot.parent_hash),
            hex::encode(leader_trace_fp),
        );

        // Additional guardrail: the proposer must still be present in the exact
        // frozen canonical snapshot used for leader selection.
        if !leader_trace
            .snapshot
            .validators
            .iter()
            .any(|w| w.eq_ignore_ascii_case(&miner_wallet_canon))
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Proposer '{}' is not present in canonical leader snapshot for block #{}",
                    miner_wallet_canon, block.metadata.index
                ),
                tx_id: Some(miner_wallet_canon),
            });
        }

        let computed_root =
            batch
                .compute_merkle_root()
                .map_err(|e| ErrorDetection::ValidationError {
                    message: format!("Failed to compute batch merkle root: {e}"),
                    tx_id: None,
                })?;
        if block.metadata.merkle_root != computed_root {
            return Err(ErrorDetection::ValidationError {
                message: "Merkle root mismatch for block batch".into(),
                tx_id: None,
            });
        }

        if block.metadata.index > 10_000_000 {
            return Err(ErrorDetection::ValidationError {
                message: format!("Block index implausibly large: {}", block.metadata.index),
                tx_id: None,
            });
        }

        let zeros64 = [0u8; 64];
        let ff64 = [0xFFu8; 64];
        if block.block_hash == zeros64 {
            return Err(ErrorDetection::ValidationError {
                message: format!("Block hash is all zeros (index {})", block.metadata.index),
                tx_id: None,
            });
        }
        if block.block_hash == ff64 {
            return Err(ErrorDetection::ValidationError {
                message: format!("Block hash is all 0xFF (index {})", block.metadata.index),
                tx_id: None,
            });
        }

        ctx.detection
            .check_block_hash_format(&hex::encode(block.block_hash))?;
        let expected_hash_hex = block.compute_block_hash()?;

        if expected_hash_hex.len() != 128 {
            return Err(ErrorDetection::SerializationError {
                details: format!(
                    "Computed block hash hex must be 128 chars (64 bytes), got {}",
                    expected_hash_hex.len()
                ),
            });
        }

        let mut expected_bytes = [0u8; 64];
        hex::decode_to_slice(&expected_hash_hex, &mut expected_bytes).map_err(|e| {
            ErrorDetection::SerializationError {
                details: format!("Decode computed hash: {e}"),
            }
        })?;

        if block.block_hash != expected_bytes {
            return Err(ErrorDetection::ValidationError {
                message: "Block hash mismatch".into(),
                tx_id: None,
            });
        }

        if !block.verify_block_signature(ctx.verifying_key)? {
            return Err(ErrorDetection::ValidationError {
                message: "Guardian signature invalid".into(),
                tx_id: None,
            });
        }

        // Mandatory ON puzzle enforcement.
        //
        // Rule:
        // - genesis must not contain a puzzle proof
        // - every non-genesis block must contain a committed puzzle proof
        // - the committed proof must verify against (height, miner, previous_hash)
        if block.metadata.index == 0 {
            if block.metadata.puzzle_proof.is_some() {
                return Err(ErrorDetection::ValidationError {
                    message: "Genesis block must not include puzzle_proof".into(),
                    tx_id: None,
                });
            }
        } else {
            let proof = block.metadata.puzzle_proof.as_ref().ok_or_else(|| {
                ErrorDetection::ValidationError {
                    message: format!(
                        "Mandatory puzzle proof missing for non-genesis block #{}",
                        block.metadata.index
                    ),
                    tx_id: None,
                }
            })?;

            proof.validate_structural()?;

            if proof.height != block.metadata.index {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Puzzle proof height mismatch: proof.height={} block.index={}",
                        proof.height, block.metadata.index
                    ),
                    tx_id: None,
                });
            }

            if proof.prev_block_hash != block.metadata.previous_hash {
                return Err(ErrorDetection::ValidationError {
                    message: "Puzzle proof prev_block_hash does not match block.previous_hash"
                        .into(),
                    tx_id: None,
                });
            }

            if !proof.validator.eq_ignore_ascii_case(&miner_wallet_canon) {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Puzzle proof validator '{}' does not match block miner '{}'",
                        proof.validator, miner_wallet_canon
                    ),
                    tx_id: None,
                });
            }

            let por_engine = PorPuzzleEngine::from_globals();
            let proof_ok = proof.verify_with_engine_checked(&por_engine)?;

            if !proof_ok {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Puzzle proof failed verification for block #{}",
                        block.metadata.index
                    ),
                    tx_id: None,
                });
            }
        }

        let reward_delay_blocks = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;
        if block.metadata.index < reward_delay_blocks {
            if block.reward != 0 {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Block reward must be zero before block {}, got {} at block {}",
                        reward_delay_blocks, block.reward, block.metadata.index
                    ),
                    tx_id: None,
                });
            }
            if batch_contains_reward_tx(batch) {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Block {} contains reward transactions before reward delay",
                        block.metadata.index
                    ),
                    tx_id: None,
                });
            }
        }

        let expected_reward = RewardHalving::get_block_reward(block.metadata.index);
        if block.reward != expected_reward {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Block reward mismatch: expected {}, got {}",
                    expected_reward, block.reward
                ),
                tx_id: None,
            });
        }

        let mut reward_sum: u64 = 0;
        for tx_kind in &batch.transactions {
            if let TxKind::Reward(reward_tx) = tx_kind {
                reward_sum = reward_sum.checked_add(reward_tx.amount).ok_or_else(|| {
                    ErrorDetection::ValidationError {
                        message: "Reward sum overflow".into(),
                        tx_id: None,
                    }
                })?;
            }
        }
        if reward_sum != block.reward {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Reward transactions total {} but block.reward is {}",
                    reward_sum, block.reward
                ),
                tx_id: None,
            });
        }

        for tx_kind in &batch.transactions {
            if let TxKind::Reward(reward_tx) = tx_kind {
                let end = reward_tx
                    .receiver
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(reward_tx.receiver.len());
                let miner =
                    std::str::from_utf8(reward_tx.receiver.get(..end).ok_or_else(|| {
                        ErrorDetection::ValidationError {
                            message: "Reward receiver slice out of bounds".into(),
                            tx_id: None,
                        }
                    })?)
                    .map_err(|_| ErrorDetection::ValidationError {
                        message: "Reward receiver is not a valid UTF-8 address".into(),
                        tx_id: None,
                    })?
                    .to_string();

                let miner_can = canon_wallet_id_checked(&miner).map_err(|e| {
                    ErrorDetection::ValidationError {
                        message: format!("Reward receiver wallet is not canonical/valid: {:?}", e),
                        tx_id: None,
                    }
                })?;

                if !ctx
                    .validator_state
                    .reward_eligible_at(&miner_can, block.metadata.index)
                {
                    let join_h_opt = ctx.validator_state.join_height(&miner_can);
                    let delay = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;

                    let eligible_at_opt = join_h_opt.map(|join_h| {
                        if join_h == 0 {
                            0
                        } else {
                            join_h.saturating_add(delay)
                        }
                    });

                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Miner {} is not reward-eligible at block {}. \
                             join_height={:?} → eligible_at={:?} (reward_delay_blocks={}).",
                            miner_can, block.metadata.index, join_h_opt, eligible_at_opt, delay
                        ),
                        tx_id: Some(miner_can),
                    });
                }
            }
        }

        let block_bytes = block.serialize_for_storage()?;
        let batch_bytes = batch.serialize()?;

        let total_bytes = block_bytes.len().saturating_add(batch_bytes.len());
        let max = match usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE) {
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

        if total_bytes > max {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Block+Batch exceeds MAX_BLOCK_SIZE: {} (block #{} bytes={}) + (batch #{} bytes={}) = {} > {}",
                    total_bytes,
                    block.metadata.index,
                    block_bytes.len(),
                    batch.index,
                    batch_bytes.len(),
                    total_bytes,
                    max
                ),
                tx_id: None,
            });
        }

        ctx.detection.check_block_size(total_bytes)?;

        tracing::debug!(
            "Block #{} validation succeeded (canonical committee + canonical leader schedule + mandatory puzzle proof verified)",
            block.metadata.index
        );
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // Deterministic anti-timewarp gate (NO local wall clock)
    // ─────────────────────────────────────────────────────────────
    fn validate_block_timestamp_deterministic(
        metadata: &BlockMetadata,
        previous_timestamp: Option<u64>,
        tm: &TimeManager,
    ) -> Result<(), ErrorDetection> {
        let height = metadata.index;
        let ts = metadata.timestamp;

        if height == 0 {
            return Ok(());
        }

        let prev_ts = previous_timestamp.ok_or_else(|| ErrorDetection::ValidationError {
            message: format!(
                "Missing previous_timestamp for non-genesis block (height={}, ts={})",
                height, ts
            ),
            tx_id: None,
        })?;

        let min_interval = GlobalConfiguration::BLOCK_CREATION_INTERVAL_SECS.max(1);
        let min_by_parent = prev_ts.saturating_add(min_interval);

        // Keep deterministic schedule anchoring aligned with the leader schedule.
        let drift = tm.slot_gate_drift_secs();
        let height_start = LeaderSchedule::height_start_unix(tm, height);
        let min_by_schedule = height_start.saturating_sub(drift);

        let min_allowed = min_by_parent.max(min_by_schedule);

        if ts < min_allowed {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Deterministic timestamp gate failed at height {}: ts={} < min_allowed={}. \
                     (prev_ts={}, min_by_parent=prev_ts+{}={}, height_start={}, drift={}s, min_by_schedule={})",
                    height,
                    ts,
                    min_allowed,
                    prev_ts,
                    min_interval,
                    min_by_parent,
                    height_start,
                    drift,
                    min_by_schedule
                ),
                tx_id: None,
            });
        }

        Ok(())
    }
}

fn batch_contains_reward_tx(batch: &TransactionBatch) -> bool {
    batch
        .transactions
        .iter()
        .any(|tx| matches!(tx, TxKind::Reward(_)))
}
