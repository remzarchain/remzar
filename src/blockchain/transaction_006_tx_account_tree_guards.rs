//! transaction_006_tx_account_tree_guards.rs

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_005_tx_account_tree::InnerTree;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use crate::network::p2p_006_reqresp::Hash;
use crate::storage::rocksdb_005_manager::RockDBManager;
use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;

/// Consensus guard kernel for AccountModelTree.
#[derive(Debug, Clone)]
pub struct AccountGuard {
    config: GuardConfig,
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub enforce_no_burn_supply_equality: bool,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            enforce_no_burn_supply_equality: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    Live,
    Replay,
}

#[derive(Debug, Clone)]
pub struct ApplyContext {
    pub mode: ApplyMode,
    pub block_height: u64,
    pub block_hash: Hash,
    pub previous_hash: Hash,
    pub allow_duplicate_reward_in_batch: bool,
}

#[derive(Debug, Clone)]
pub struct BatchApplyOutcome {
    pub touched_accounts: BTreeSet<String>,
    pub total_supply_micro: u64,
    pub fingerprint_hex: String,
}

#[derive(Debug, Clone)]
pub struct StateFingerprint {
    pub height: u64,
    pub total_issued_micro: u64,
    pub rewards_issued_micro: u64,
    pub total_supply_micro: u64,
    pub touched_accounts: Vec<(String, u64)>,
    pub hex: String,
}

/// Full canonical history must live in RocksDB.
const MAX_RECENT_BLOCKS_IN_RAM: usize = 512;

/// Account keys are canonical wallet strings in normal paths: "r" + 128 hex = 129 bytes.
const MAX_ACCOUNT_KEY_BYTES: usize = 256;

/// TxKind variant from accidentally creating unbounded touched-account sets.
const MAX_TOUCHED_ACCOUNTS_PER_TX: usize = 4;

/// Fingerprint domain separator.
const ACCOUNT_STATE_FINGERPRINT_DOMAIN: &str = "REMZAR_ACCOUNT_STATE_FINGERPRINT_V2";

impl AccountGuard {
    pub fn new() -> Self {
        Self {
            config: GuardConfig::default(),
        }
    }

    pub fn with_config(config: GuardConfig) -> Self {
        Self { config }
    }

    /// Deterministic validator for a batch before state mutation.
    pub(crate) fn validate_batch_structure(
        &self,
        batch: &TransactionBatch,
    ) -> Result<(), ErrorDetection> {
        self.validate_batch_structure_with_reward_policy(batch, false)
    }

    /// Deterministic validator for a batch before state mutation.
    ///
    /// This version keeps the duplicate-reward policy explicit because replay
    /// and migration code may need a narrow compatibility escape hatch, while
    /// normal live consensus should reject multiple rewards in one batch.
    pub(crate) fn validate_batch_structure_with_reward_policy(
        &self,
        batch: &TransactionBatch,
        allow_duplicate_reward_in_batch: bool,
    ) -> Result<(), ErrorDetection> {
        self.validate_batch_payload_size(batch)?;

        let max_txs_per_block = max_txs_per_block_usize()?;

        if batch.transactions.len() > max_txs_per_block {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Batch {} contains too many transactions: {} > {}",
                    batch.index,
                    batch.transactions.len(),
                    GlobalConfiguration::MAX_TXS_PER_BLOCK
                ),
                tx_id: None,
            });
        }

        let mut seen_transfer_ids = HashSet::new();
        let mut reward_count = 0usize;

        for kind in &batch.transactions {
            match kind {
                TxKind::Transfer(tx) => {
                    let sender = normalize_wallet_bytes(&tx.sender);
                    let receiver = normalize_wallet_bytes(&tx.receiver);

                    if tx.amount == 0 {
                        return Err(ErrorDetection::ValidationError {
                            message: "Transfer tx amount must be non-zero".into(),
                            tx_id: None,
                        });
                    }

                    validate_account_key_string(&sender, "Transfer sender")?;
                    validate_account_key_string(&receiver, "Transfer receiver")?;

                    if sender == receiver {
                        return Err(ErrorDetection::ValidationError {
                            message: "Transfer tx sender and receiver cannot be the same".into(),
                            tx_id: None,
                        });
                    }

                    if tx.amount > GlobalConfiguration::MAX_TX_AMOUNT {
                        return Err(ErrorDetection::ValidationError {
                            message: format!(
                                "Transfer tx amount {} exceeds allowed max {}",
                                tx.amount,
                                GlobalConfiguration::MAX_TX_AMOUNT
                            ),
                            tx_id: None,
                        });
                    }

                    let id = tx.id()?;
                    if !seen_transfer_ids.insert(id) {
                        return Err(ErrorDetection::ValidationError {
                            message: "Duplicate transfer transaction detected in batch".into(),
                            tx_id: None,
                        });
                    }
                }

                TxKind::Reward(rew) => {
                    reward_count = reward_count.saturating_add(1);

                    let receiver = normalize_wallet_bytes(&rew.receiver);

                    if rew.amount == 0 {
                        return Err(ErrorDetection::ValidationError {
                            message: "Reward tx amount must be non-zero".into(),
                            tx_id: None,
                        });
                    }

                    validate_account_key_string(&receiver, "Reward receiver")?;

                    if rew.amount > GlobalConfiguration::MAX_BLOCK_REWARD {
                        return Err(ErrorDetection::ValidationError {
                            message: format!(
                                "Reward tx amount {} exceeds max block reward {}",
                                rew.amount,
                                GlobalConfiguration::MAX_BLOCK_REWARD
                            ),
                            tx_id: None,
                        });
                    }
                }

                TxKind::RegisterNode(reg) => {
                    let wallet = normalize_wallet_bytes(&reg.wallet_address);
                    validate_account_key_string(&wallet, "RegisterNode wallet")?;
                }

                TxKind::NftMint(_) | TxKind::NftTransfer(_) => {}
            }
        }

        if !allow_duplicate_reward_in_batch && reward_count > 1 {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Batch {} contains multiple reward transactions: {}",
                    batch.index, reward_count
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    /// Deterministic batch application into a provided state snapshot.
    ///
    /// Compact-state rule:
    /// `InnerTree.blocks` is only a bounded recent cache. This method therefore
    /// validates account/supply invariants using compact tip metadata instead
    /// of assuming `blocks.len() == chain height + 1`.
    pub(crate) fn apply_batch_to_state(
        &self,
        state: &mut InnerTree,
        batch: &TransactionBatch,
        ctx: &ApplyContext,
    ) -> Result<BatchApplyOutcome, ErrorDetection> {
        self.validate_apply_context(ctx)?;

        self.validate_batch_structure_with_reward_policy(
            batch,
            ctx.allow_duplicate_reward_in_batch,
        )?;

        if batch.index != ctx.block_height {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Batch index {} does not match context block height {}",
                    batch.index, ctx.block_height
                ),
                tx_id: None,
            });
        }

        let mut spend_per_sender: BTreeMap<String, u64> = BTreeMap::new();

        for kind in &batch.transactions {
            if let TxKind::Transfer(tx) = kind {
                let sender = normalize_wallet_bytes(&tx.sender);
                let entry = spend_per_sender.entry(sender).or_insert(0);
                *entry = entry.checked_add(tx.amount).ok_or_else(|| {
                    ErrorDetection::ValidationError {
                        message: "Overflow while aggregating per-sender batch spend".into(),
                        tx_id: None,
                    }
                })?;
            }
        }

        for (sender, total_spend) in &spend_per_sender {
            let bal = state.balances.get(sender).copied().unwrap_or(0);
            if bal < *total_spend {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Insufficient balance for {}: need {}, have {}",
                        sender, total_spend, bal
                    ),
                    tx_id: None,
                });
            }
        }

        let mut touched = BTreeSet::new();

        for kind in &batch.transactions {
            self.apply_txkind_to_state(state, kind, ctx, &mut touched)?;
        }

        verify_touched_account_bound(batch, &touched)?;

        self.verify_state_invariants(state, None, None, None)?;

        let fp = self.compute_state_fingerprint_for_context(state, ctx, &touched)?;

        Ok(BatchApplyOutcome {
            touched_accounts: touched,
            total_supply_micro: fp.total_supply_micro,
            fingerprint_hex: fp.hex,
        })
    }

    /// Shared deterministic mutation engine for a single TxKind.
    pub(crate) fn apply_txkind_to_state(
        &self,
        state: &mut InnerTree,
        kind: &TxKind,
        _ctx: &ApplyContext,
        touched: &mut BTreeSet<String>,
    ) -> Result<(), ErrorDetection> {
        match kind {
            TxKind::Transfer(tx) => {
                let sender = normalize_wallet_bytes(&tx.sender);
                let receiver = normalize_wallet_bytes(&tx.receiver);
                validate_account_key_string(&sender, "Transfer sender")?;
                validate_account_key_string(&receiver, "Transfer receiver")?;

                let sender_entry = state.balances.entry(sender.clone()).or_insert(0);
                *sender_entry = sender_entry.checked_sub(tx.amount).ok_or_else(|| {
                    ErrorDetection::ValidationError {
                        message: format!("Transfer underflow on sender {}", sender),
                        tx_id: None,
                    }
                })?;

                let receiver_entry = state.balances.entry(receiver.clone()).or_insert(0);
                *receiver_entry = receiver_entry.checked_add(tx.amount).ok_or_else(|| {
                    ErrorDetection::ValidationError {
                        message: format!(
                            "Transfer overflow crediting receiver {} by {}",
                            receiver, tx.amount
                        ),
                        tx_id: None,
                    }
                })?;

                if *receiver_entry > GlobalConfiguration::MAX_SUPPLY {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Receiver {} balance exceeds MAX_SUPPLY after transfer",
                            receiver
                        ),
                        tx_id: None,
                    });
                }

                touched.insert(sender);
                touched.insert(receiver);
            }

            TxKind::Reward(rew) => {
                let receiver = normalize_wallet_bytes(&rew.receiver);
                validate_account_key_string(&receiver, "Reward receiver")?;

                let new_rewards_issued = state
                    .rewards_issued_micro
                    .checked_add(rew.amount)
                    .ok_or_else(|| ErrorDetection::ValidationError {
                        message: "Overflow rewards_issued_micro".into(),
                        tx_id: None,
                    })?;

                let new_total_issued = state
                    .total_issued_micro
                    .checked_add(rew.amount)
                    .ok_or_else(|| ErrorDetection::ValidationError {
                        message: "Overflow total_issued_micro".into(),
                        tx_id: None,
                    })?;

                if new_total_issued > GlobalConfiguration::MAX_SUPPLY {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Mint cap exceeded: total_issued {} > MAX_SUPPLY {}",
                            new_total_issued,
                            GlobalConfiguration::MAX_SUPPLY
                        ),
                        tx_id: None,
                    });
                }

                let receiver_entry = state.balances.entry(receiver.clone()).or_insert(0);
                *receiver_entry = receiver_entry.checked_add(rew.amount).ok_or_else(|| {
                    ErrorDetection::ValidationError {
                        message: format!(
                            "Reward overflow crediting receiver {} by {}",
                            receiver, rew.amount
                        ),
                        tx_id: None,
                    }
                })?;

                if *receiver_entry > GlobalConfiguration::MAX_SUPPLY {
                    return Err(ErrorDetection::ValidationError {
                        message: format!(
                            "Receiver {} balance exceeds MAX_SUPPLY after reward",
                            receiver
                        ),
                        tx_id: None,
                    });
                }

                state.rewards_issued_micro = new_rewards_issued;
                state.total_issued_micro = new_total_issued;

                touched.insert(receiver);
            }

            TxKind::RegisterNode(reg) => {
                let wallet = normalize_wallet_bytes(&reg.wallet_address);
                validate_account_key_string(&wallet, "RegisterNode wallet")?;
                touched.insert(wallet);
            }

            TxKind::NftMint(_) | TxKind::NftTransfer(_) => {}
        }

        Ok(())
    }

    /// Hard invariant checks after state mutation, replay, or migration.
    ///
    /// Compact-state rule:
    /// - `state.tip_height`, `state.tip_hash`, and `state.prev_tip_hash` are the
    ///   canonical compact chain metadata.
    /// - `state.blocks` is only a bounded recent cache. It may be empty after
    ///   loading a compact snapshot and must never be treated as full history.
    pub(crate) fn verify_state_invariants(
        &self,
        state: &InnerTree,
        expected_tip_height: Option<u64>,
        expected_tip_hash: Option<Hash>,
        expected_prev_hash: Option<Hash>,
    ) -> Result<(), ErrorDetection> {
        verify_compact_tip_shape(state)?;

        let mut accounts: Vec<&String> = state.balances.keys().collect();
        accounts.sort_unstable();

        for acct in accounts {
            validate_account_key_string(acct, "Account state key")?;

            let bal = state.balances.get(acct).copied().ok_or_else(|| {
                ErrorDetection::ValidationError {
                    message: format!(
                        "Invariant violation: account {} disappeared during verification",
                        acct
                    ),
                    tx_id: None,
                }
            })?;

            if bal > GlobalConfiguration::MAX_SUPPLY {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Invariant violation: account {} balance {} exceeds MAX_SUPPLY {}",
                        acct,
                        bal,
                        GlobalConfiguration::MAX_SUPPLY
                    ),
                    tx_id: None,
                });
            }
        }

        let total_supply = sum_balances_checked(&state.balances)?;

        if total_supply > GlobalConfiguration::MAX_SUPPLY {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: total_supply {} exceeds MAX_SUPPLY {}",
                    total_supply,
                    GlobalConfiguration::MAX_SUPPLY
                ),
                tx_id: None,
            });
        }

        if state.rewards_issued_micro > state.total_issued_micro {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: rewards_issued_micro {} > total_issued_micro {}",
                    state.rewards_issued_micro, state.total_issued_micro
                ),
                tx_id: None,
            });
        }

        if state.total_issued_micro > GlobalConfiguration::MAX_SUPPLY {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: total_issued_micro {} > MAX_SUPPLY {}",
                    state.total_issued_micro,
                    GlobalConfiguration::MAX_SUPPLY
                ),
                tx_id: None,
            });
        }

        if self.config.enforce_no_burn_supply_equality && total_supply != state.total_issued_micro {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: total_supply {} != total_issued_micro {}",
                    total_supply, state.total_issued_micro
                ),
                tx_id: None,
            });
        }

        verify_recent_block_cache(state)?;
        verify_recent_cache_not_full_history_regression(state)?;

        if let Some(expected_height) = expected_tip_height {
            if !state.has_tip {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Invariant violation: expected tip height {}, but state has no tip",
                        expected_height
                    ),
                    tx_id: None,
                });
            }

            if state.tip_height != expected_height {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Invariant violation: expected tip height {}, got {}",
                        expected_height, state.tip_height
                    ),
                    tx_id: None,
                });
            }
        }

        if let Some(expected_hash) = expected_tip_hash
            && (!state.has_tip || state.tip_hash != expected_hash)
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: expected tip hash {}, got {}",
                    hex::encode(expected_hash),
                    hex::encode(state.tip_hash)
                ),
                tx_id: None,
            });
        }

        if let Some(prev_hash_expected) = expected_prev_hash
            && (!state.has_tip || state.prev_tip_hash != prev_hash_expected)
        {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: expected previous tip hash {}, got {}",
                    hex::encode(prev_hash_expected),
                    hex::encode(state.prev_tip_hash)
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    /// Idempotency helper aligned with compact state.
    ///
    /// For old heights outside the bounded recent cache, this returns `Ok(true)`.
    /// That means "already handled / do not re-apply from RAM-only guard view".
    /// Reorg and historical conflict checks must use the DB-backed chain path.
    pub(crate) fn check_canonical_idempotency(
        &self,
        state: &InnerTree,
        block: &Block,
    ) -> Result<bool, ErrorDetection> {
        if !state.has_tip {
            return Ok(false);
        }

        if block.metadata.index == state.tip_height {
            if block.block_hash == state.tip_hash {
                return Ok(true);
            }

            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Conflicting canonical tip at height {}: existing={} incoming={}",
                    block.metadata.index,
                    hex::encode(state.tip_hash),
                    hex::encode(block.block_hash)
                ),
                tx_id: None,
            });
        }

        if block.metadata.index > state.tip_height {
            return Ok(false);
        }

        if let Some(existing) = state
            .blocks
            .iter()
            .find(|existing| existing.metadata.index == block.metadata.index)
        {
            if existing.block_hash == block.block_hash {
                return Ok(true);
            }

            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Conflicting recent canonical block at height {}: existing={} incoming={}",
                    block.metadata.index,
                    hex::encode(existing.block_hash),
                    hex::encode(block.block_hash)
                ),
                tx_id: None,
            });
        }

        Ok(true)
    }

    /// Dry-run helper for apply_block.
    pub(crate) fn dry_run_block_and_batch(
        &self,
        mut tentative_state: InnerTree,
        block: &Block,
        batch: &TransactionBatch,
    ) -> Result<(InnerTree, BatchApplyOutcome), ErrorDetection> {
        let expected_height = tentative_state.expected_next_height();

        if block.metadata.index != expected_height {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Dry-run expected next height {}, got {}",
                    expected_height, block.metadata.index
                ),
                tx_id: None,
            });
        }

        let prev_hash: Hash = if tentative_state.has_tip {
            if block.metadata.previous_hash != tentative_state.tip_hash {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "Dry-run previous_hash mismatch at height {}: expected {}, got {}",
                        block.metadata.index,
                        hex::encode(tentative_state.tip_hash),
                        hex::encode(block.metadata.previous_hash)
                    ),
                    tx_id: None,
                });
            }

            tentative_state.tip_hash
        } else {
            block.metadata.previous_hash
        };

        remember_recent_block_for_guard(&mut tentative_state, block.clone());

        let ctx = ApplyContext {
            mode: ApplyMode::Live,
            block_height: block.metadata.index,
            block_hash: block.block_hash,
            previous_hash: prev_hash,
            allow_duplicate_reward_in_batch: false,
        };

        let outcome = self.apply_batch_to_state(&mut tentative_state, batch, &ctx)?;

        self.verify_state_invariants(
            &tentative_state,
            Some(block.metadata.index),
            Some(block.block_hash),
            Some(prev_hash),
        )?;

        Ok((tentative_state, outcome))
    }

    /// Optional derived-view checker after flush.
    pub(crate) fn verify_account_cf_matches_state(
        &self,
        db: &RockDBManager,
        state: &InnerTree,
        touched_accounts: &BTreeSet<String>,
    ) -> Result<(), ErrorDetection> {
        for acct in touched_accounts {
            let expected = state.balances.get(acct).copied().unwrap_or(0);

            let raw = db.read(GlobalConfiguration::ACCOUNT_COLUMN_NAME, acct.as_bytes())?;
            let bytes = raw.ok_or_else(|| ErrorDetection::ValidationError {
                message: format!("ACCOUNT CF missing touched account {}", acct),
                tx_id: None,
            })?;

            let (actual, remaining): (u64, &[u8]) =
                postcard::take_from_bytes(&bytes).map_err(|e| {
                    ErrorDetection::SerializationError {
                        details: format!("Failed to decode ACCOUNT CF balance for {}: {}", acct, e),
                    }
                })?;

            if !remaining.is_empty() {
                return Err(ErrorDetection::SerializationError {
                    details: format!(
                        "ACCOUNT CF balance for {} has trailing bytes: {}",
                        acct,
                        remaining.len()
                    ),
                });
            }

            if actual != expected {
                return Err(ErrorDetection::ValidationError {
                    message: format!(
                        "ACCOUNT CF mismatch for {}: expected {}, got {}",
                        acct, expected, actual
                    ),
                    tx_id: None,
                });
            }
        }

        Ok(())
    }

    fn validate_batch_payload_size(&self, batch: &TransactionBatch) -> Result<(), ErrorDetection> {
        let serialized_len = batch.serialized_len()?;
        let cap = max_batch_serialized_bytes()?;

        if serialized_len > cap {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Batch {} serialized length {} exceeds guarded cap {}",
                    batch.index, serialized_len, cap
                ),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn validate_apply_context(&self, ctx: &ApplyContext) -> Result<(), ErrorDetection> {
        if ctx.block_hash == zero_hash() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "ApplyContext for height {} has all-zero block_hash",
                    ctx.block_height
                ),
                tx_id: None,
            });
        }

        if ctx.block_height > 0 && ctx.previous_hash == zero_hash() {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "ApplyContext for non-genesis height {} has all-zero previous_hash",
                    ctx.block_height
                ),
                tx_id: None,
            });
        }

        if matches!(ctx.mode, ApplyMode::Live) && ctx.allow_duplicate_reward_in_batch {
            return Err(ErrorDetection::ValidationError {
                message: "Live ApplyContext cannot allow duplicate reward transactions".into(),
                tx_id: None,
            });
        }

        Ok(())
    }

    fn compute_state_fingerprint_for_context(
        &self,
        state: &InnerTree,
        ctx: &ApplyContext,
        touched_accounts: &BTreeSet<String>,
    ) -> Result<StateFingerprint, ErrorDetection> {
        self.compute_state_fingerprint_with_values(
            state,
            ctx.block_height,
            ctx.block_hash,
            ctx.previous_hash,
            touched_accounts,
        )
    }

    fn compute_state_fingerprint_with_values(
        &self,
        state: &InnerTree,
        height: u64,
        block_hash: Hash,
        previous_hash: Hash,
        touched_accounts: &BTreeSet<String>,
    ) -> Result<StateFingerprint, ErrorDetection> {
        let total_supply = sum_balances_checked(&state.balances)?;

        let mut touched = Vec::with_capacity(touched_accounts.len());
        for acct in touched_accounts {
            touched.push((acct.clone(), state.balances.get(acct).copied().unwrap_or(0)));
        }

        let mut hasher = StableHasher::new();
        hasher.update_str(ACCOUNT_STATE_FINGERPRINT_DOMAIN);
        hasher.update_u64(height);
        hasher.update_u64(state.total_issued_micro);
        hasher.update_u64(state.rewards_issued_micro);
        hasher.update_u64(total_supply);
        hasher.update_bool(state.has_tip);
        hasher.update_u64(state.tip_height);
        hasher.update_hash64(&state.tip_hash);
        hasher.update_hash64(&state.prev_tip_hash);
        hasher.update_hash64(&block_hash);
        hasher.update_hash64(&previous_hash);

        for (acct, bal) in &touched {
            hasher.update_str(acct);
            hasher.update_u64(*bal);
        }

        Ok(StateFingerprint {
            height,
            total_issued_micro: state.total_issued_micro,
            rewards_issued_micro: state.rewards_issued_micro,
            total_supply_micro: total_supply,
            touched_accounts: touched,
            hex: hasher.finish_hex_128(),
        })
    }
}

impl Default for AccountGuard {
    fn default() -> Self {
        Self::new()
    }
}

fn zero_hash() -> Hash {
    [0u8; 64]
}

fn max_txs_per_block_usize() -> Result<usize, ErrorDetection> {
    usize::try_from(GlobalConfiguration::MAX_TXS_PER_BLOCK).map_err(|_| {
        ErrorDetection::ValidationError {
            message: format!(
                "Invalid MAX_TXS_PER_BLOCK (cannot fit into usize): {}",
                GlobalConfiguration::MAX_TXS_PER_BLOCK
            ),
            tx_id: None,
        }
    })
}

fn max_batch_serialized_bytes() -> Result<usize, ErrorDetection> {
    let max_block_size = usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).map_err(|_| {
        ErrorDetection::ValidationError {
            message: format!(
                "Invalid MAX_BLOCK_SIZE (cannot fit into usize): {}",
                GlobalConfiguration::MAX_BLOCK_SIZE
            ),
            tx_id: None,
        }
    })?;

    max_block_size
        .checked_add(GlobalConfiguration::MAX_BATCH_SERIALIZED_OVERHEAD)
        .ok_or_else(|| ErrorDetection::ValidationError {
            message: "MAX_BLOCK_SIZE + MAX_BATCH_SERIALIZED_OVERHEAD overflows usize".into(),
            tx_id: None,
        })
}

fn validate_account_key_string(account: &str, label: &str) -> Result<(), ErrorDetection> {
    if account.is_empty() {
        return Err(ErrorDetection::ValidationError {
            message: format!("{label} must be non-empty"),
            tx_id: None,
        });
    }

    if account.len() > MAX_ACCOUNT_KEY_BYTES {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "{label} is too long: {} > {} bytes",
                account.len(),
                MAX_ACCOUNT_KEY_BYTES
            ),
            tx_id: None,
        });
    }

    if account.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(ErrorDetection::ValidationError {
            message: format!("{label} contains ASCII control bytes"),
            tx_id: None,
        });
    }

    Ok(())
}

fn verify_touched_account_bound(
    batch: &TransactionBatch,
    touched: &BTreeSet<String>,
) -> Result<(), ErrorDetection> {
    let by_tx_cap = batch
        .transactions
        .len()
        .checked_mul(MAX_TOUCHED_ACCOUNTS_PER_TX)
        .ok_or_else(|| ErrorDetection::ValidationError {
            message: "Touched-account cap overflowed usize".into(),
            tx_id: None,
        })?;

    let hard_cap = max_txs_per_block_usize()?
        .checked_mul(MAX_TOUCHED_ACCOUNTS_PER_TX)
        .ok_or_else(|| ErrorDetection::ValidationError {
            message: "Global touched-account cap overflowed usize".into(),
            tx_id: None,
        })?;

    let cap = by_tx_cap.min(hard_cap);

    if touched.len() > cap {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Touched-account set too large for batch {}: {} > {}",
                batch.index,
                touched.len(),
                cap
            ),
            tx_id: None,
        });
    }

    Ok(())
}

fn verify_compact_tip_shape(state: &InnerTree) -> Result<(), ErrorDetection> {
    if !state.has_tip {
        if state.tip_height != 0
            || state.tip_hash != zero_hash()
            || state.prev_tip_hash != zero_hash()
        {
            return Err(ErrorDetection::ValidationError {
                message: "Invariant violation: no-tip state must have zero tip metadata".into(),
                tx_id: None,
            });
        }

        return Ok(());
    }

    if state.tip_hash == zero_hash() {
        return Err(ErrorDetection::ValidationError {
            message: "Invariant violation: compact state has_tip=true but tip_hash is zero".into(),
            tx_id: None,
        });
    }

    if state.tip_height > 0 && state.prev_tip_hash == zero_hash() {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Invariant violation: non-genesis compact tip {} has zero prev_tip_hash",
                state.tip_height
            ),
            tx_id: None,
        });
    }

    Ok(())
}

fn verify_recent_cache_not_full_history_regression(
    state: &InnerTree,
) -> Result<(), ErrorDetection> {
    if !state.has_tip || state.blocks.len() < MAX_RECENT_BLOCKS_IN_RAM {
        return Ok(());
    }

    let Some(first) = state.blocks.first() else {
        return Ok(());
    };

    // At heights >= MAX_RECENT_BLOCKS_IN_RAM, a recent cache starting at 0 is a
    // strong signal that somebody reintroduced "all blocks since genesis" logic.
    if state.tip_height >= u64::try_from(MAX_RECENT_BLOCKS_IN_RAM).unwrap_or(u64::MAX)
        && first.metadata.index == 0
    {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Invariant violation: recent block cache appears to contain genesis-to-tip history at tip {} (len {}). Full history must stay in RocksDB.",
                state.tip_height,
                state.blocks.len()
            ),
            tx_id: None,
        });
    }

    Ok(())
}

fn verify_recent_block_cache(state: &InnerTree) -> Result<(), ErrorDetection> {
    if state.blocks.len() > MAX_RECENT_BLOCKS_IN_RAM {
        return Err(ErrorDetection::ValidationError {
            message: format!(
                "Invariant violation: recent block cache len {} exceeds max {}",
                state.blocks.len(),
                MAX_RECENT_BLOCKS_IN_RAM
            ),
            tx_id: None,
        });
    }

    if !state.has_tip {
        if !state.blocks.is_empty() {
            return Err(ErrorDetection::ValidationError {
                message: "Invariant violation: state has recent blocks but no compact tip".into(),
                tx_id: None,
            });
        }

        return Ok(());
    }

    verify_contiguous_recent_blocks(&state.blocks)?;

    if let Some(last) = state.blocks.last() {
        if last.metadata.index != state.tip_height || last.block_hash != state.tip_hash {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: recent cache tip mismatch: cache_height={} compact_height={} cache_hash={} compact_hash={}",
                    last.metadata.index,
                    state.tip_height,
                    hex::encode(last.block_hash),
                    hex::encode(state.tip_hash)
                ),
                tx_id: None,
            });
        }

        if state.tip_height == 0 {
            if state.prev_tip_hash != last.metadata.previous_hash {
                return Err(ErrorDetection::ValidationError {
                    message: "Invariant violation: genesis prev_tip_hash does not match genesis previous_hash".into(),
                    tx_id: None,
                });
            }
        } else if last.metadata.previous_hash != state.prev_tip_hash {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: recent tip previous_hash mismatch at height {}",
                    last.metadata.index
                ),
                tx_id: None,
            });
        }
    }

    Ok(())
}

fn verify_contiguous_recent_blocks(blocks: &[Block]) -> Result<(), ErrorDetection> {
    for pair in blocks.windows(2) {
        let [prev, block] = pair else {
            return Err(ErrorDetection::ValidationError {
                message: "Invariant violation: recent block window length was not 2".into(),
                tx_id: None,
            });
        };

        if block.metadata.index != prev.metadata.index.saturating_add(1) {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: non-contiguous recent block cache: {} then {}",
                    prev.metadata.index, block.metadata.index
                ),
                tx_id: None,
            });
        }

        if block.metadata.previous_hash != prev.block_hash {
            return Err(ErrorDetection::ValidationError {
                message: format!(
                    "Invariant violation: previous_hash mismatch in recent cache at height {}",
                    block.metadata.index
                ),
                tx_id: None,
            });
        }
    }

    Ok(())
}

fn remember_recent_block_for_guard(state: &mut InnerTree, block: Block) {
    let prev_hash = if state.has_tip {
        state.tip_hash
    } else {
        block.metadata.previous_hash
    };

    state.prev_tip_hash = prev_hash;
    state.tip_height = block.metadata.index;
    state.tip_hash = block.block_hash;
    state.has_tip = true;

    let already_last = state
        .blocks
        .last()
        .map(|last| {
            last.metadata.index == block.metadata.index && last.block_hash == block.block_hash
        })
        .unwrap_or(false);

    if !already_last {
        state.blocks.push(block);
    }

    if state.blocks.len() > MAX_RECENT_BLOCKS_IN_RAM {
        let excess = state.blocks.len().saturating_sub(MAX_RECENT_BLOCKS_IN_RAM);
        state.blocks.drain(0..excess);
    }
}

fn normalize_wallet_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .trim()
        .to_string()
}

fn sum_balances_checked(balances: &HashMap<String, u64>) -> Result<u64, ErrorDetection> {
    balances.values().copied().try_fold(0u64, |acc, value| {
        acc.checked_add(value)
            .ok_or_else(|| ErrorDetection::ValidationError {
                message: "Overflow while summing balances".into(),
                tx_id: None,
            })
    })
}

#[derive(Debug, Clone)]
struct StableHasher {
    lo: u64,
    hi: u64,
}

impl StableHasher {
    fn new() -> Self {
        Self {
            lo: 0xcbf29ce484222325,
            hi: 0x84222325cbf29ce4,
        }
    }

    fn update_bytes(&mut self, bytes: &[u8]) {
        const P1: u64 = 0x100000001b3;
        const P2: u64 = 0x9e3779b185ebca87;

        for byte in bytes {
            self.lo ^= u64::from(*byte);
            self.lo = self.lo.wrapping_mul(P1);

            self.hi ^= u64::from(*byte).rotate_left(1);
            self.hi = self.hi.wrapping_mul(P2);
        }
    }

    fn update_bool(&mut self, value: bool) {
        self.update_bytes(&[u8::from(value)]);
    }

    fn update_hash64(&mut self, value: &Hash) {
        self.update_bytes(value);
    }

    fn update_str(&mut self, value: &str) {
        let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.update_u64(len);
        self.update_bytes(value.as_bytes());
    }

    /// Consensus diagnostic encoding uses big-endian u64 bytes.
    fn update_u64(&mut self, value: u64) {
        self.update_bytes(&value.to_be_bytes());
    }

    fn finish_hex_128(&self) -> String {
        format!("{:016x}{:016x}", self.hi, self.lo)
    }
}
