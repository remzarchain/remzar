use std::collections::BTreeMap;

use crate::blockchain::block_002_blocks::Block;
use crate::blockchain::transaction_002_tx_register::RegisterNodeTx;
use crate::blockchain::transaction_004_tx_kind::TxKind;
use crate::blockchain::transaction_005_tx_batch::TransactionBatch;
use postcard::{from_bytes, to_allocvec};

use crate::consensus::por_008_validator_lifecycle::{
    RegisterOutcome, ValidatorLifecycle, ValidatorLifecycleConfig, ValidatorMeta,
};

use crate::storage::rocksdb_005_manager::RockDBManager;

use crate::utility::alpha_001_global_configuration::GlobalConfiguration;
use crate::utility::alpha_002_error_detection_system::ErrorDetection;
use crate::utility::helper::canon_wallet_id_checked;
use crate::utility::time_policy::TimePolicy;

/// Dedicated key under `STATE_COLUMN_NAME` for validator state snapshot.
const VALIDATOR_STATE_KEY: &[u8] = b"validator_state_v1";

/// Dedicated key under `STATE_COLUMN_NAME` for a persistent, monotonic latch.
const MULTI_VALIDATOR_EVER_SEEN_KEY: &[u8] = b"validator_multi_validator_ever_seen_v1";

/// On-chain validator registry state.
#[derive(Debug, Clone)]
pub struct ValidatorState {
    inner: BTreeMap<String, ValidatorMeta>,
    db_manager: RockDBManager,
}

impl ValidatorState {
    // ─────────────────────────────────────────────────────────────
    // Constructors / persistence
    // ─────────────────────────────────────────────────────────────

    pub fn with_manager(db_manager: RockDBManager) -> Self {
        Self {
            inner: BTreeMap::new(),
            db_manager,
        }
    }

    pub fn load_state(db_manager: RockDBManager) -> Result<Self, ErrorDetection> {
        let maybe_bytes =
            db_manager.read(GlobalConfiguration::STATE_COLUMN_NAME, VALIDATOR_STATE_KEY)?;

        let bytes = maybe_bytes.ok_or_else(|| ErrorDetection::NotFound {
            resource: "ValidatorState".into(),
        })?;

        let map: BTreeMap<String, ValidatorMeta> =
            from_bytes(&bytes).map_err(|e| ErrorDetection::SerializationError {
                details: format!("ValidatorState deserialize failed: {e}"),
            })?;

        ValidatorLifecycle::config().validate()?;
        ValidatorLifecycle::validate_map(&map)?;

        Ok(Self {
            inner: map,
            db_manager,
        })
    }

    pub fn load_or_new(db_manager: RockDBManager) -> Result<Self, ErrorDetection> {
        match Self::load_state(db_manager.clone()) {
            Ok(vs) => Ok(vs),

            Err(ErrorDetection::NotFound { .. }) => Ok(Self::with_manager(db_manager)),

            // Backward-compatible upgrade path.
            Err(ErrorDetection::SerializationError { .. }) => {
                let mut vs = Self::with_manager(db_manager);
                vs.rebuild_from_chain(None)?;
                Ok(vs)
            }

            Err(e) => Err(e),
        }
    }

    pub fn commit(&self) -> Result<(), ErrorDetection> {
        ValidatorLifecycle::config().validate()?;
        ValidatorLifecycle::validate_map(&self.inner)?;

        let bytes = to_allocvec(&self.inner).map_err(|e| ErrorDetection::SerializationError {
            details: format!("ValidatorState serialize failed: {e}"),
        })?;

        self.db_manager
            .write(
                GlobalConfiguration::STATE_COLUMN_NAME,
                VALIDATOR_STATE_KEY,
                &bytes,
            )
            .map_err(|e| ErrorDetection::StorageError {
                message: format!("ValidatorState write failed: {e}"),
            })
    }

    // ─────────────────────────────────────────────────────────────
    // Canonical founder derivation (single source of truth)
    // ─────────────────────────────────────────────────────────────

    /// Derive the canonical founder validator from canonical block-0 data.
    fn derive_genesis_founder_from_chain(
        db: &RockDBManager,
    ) -> Result<Option<(String, u64)>, ErrorDetection> {
        let maybe_genesis_block: Option<Block> = db.get_block_by_index(0)?;

        let Some(genesis_block) = maybe_genesis_block else {
            return Ok(None);
        };

        if genesis_block.metadata.index != 0 {
            return Err(validation_err(format!(
                "ValidatorState::derive_genesis_founder_from_chain expected block 0 but loaded metadata.index={}",
                genesis_block.metadata.index
            )));
        }

        let founder_wallet_raw = genesis_block.miner.as_str();
        let founder_timestamp = TimePolicy::canonical_event_timestamp_from_block(
            "ValidatorState.genesis_founder.timestamp",
            genesis_block.metadata.timestamp,
        )?;

        let founder_wallet = canon_wallet_id_checked(founder_wallet_raw).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!(
                    "ValidatorState::derive_genesis_founder_from_chain invalid genesis founder wallet: {e}"
                ),
                tx_id: None,
            }
        })?;

        Ok(Some((founder_wallet, founder_timestamp)))
    }

    /// Seed founder semantics from canonical block-0 data into a replay map.
    fn seed_founder_from_canonical_genesis(
        map: &mut BTreeMap<String, ValidatorMeta>,
        db: &RockDBManager,
    ) -> Result<(), ErrorDetection> {
        let Some((founder_wallet, join_timestamp)) = Self::derive_genesis_founder_from_chain(db)?
        else {
            return Ok(());
        };

        match map.get(&founder_wallet) {
            Some(existing) if existing.join_height == 0 && existing.exit_height.is_none() => {
                return Ok(());
            }
            Some(_) | None => {}
        }

        let founder_meta = ValidatorLifecycle::founder_meta(join_timestamp)?;
        map.insert(founder_wallet, founder_meta);

        Ok(())
    }

    /// Explicit helper retained for existing call sites that seed founder during genesis init.
    pub fn seed_genesis_founder(
        &mut self,
        founder_wallet: &str,
        join_timestamp: u64,
    ) -> Result<(), ErrorDetection> {
        let founder_can = canon_wallet_id_checked(founder_wallet).map_err(|e| {
            ErrorDetection::ValidationError {
                message: format!("ValidatorState::seed_genesis_founder invalid wallet: {e}"),
                tx_id: None,
            }
        })?;

        let join_timestamp = TimePolicy::canonical_event_timestamp_from_block(
            "ValidatorState.seed_genesis_founder.join_timestamp",
            join_timestamp,
        )?;

        match self.inner.get(&founder_can) {
            Some(existing) if existing.join_height == 0 && existing.exit_height.is_none() => {
                return Ok(());
            }
            Some(_) | None => {}
        }

        let founder_meta = ValidatorLifecycle::founder_meta(join_timestamp)?;
        self.inner.insert(founder_can, founder_meta);

        self.commit()?;
        self.persist_multi_validator_latch_if_needed()?;
        Ok(())
    }

    pub fn is_canonically_known(&self, wallet: &str) -> Result<bool, ErrorDetection> {
        let wallet_can =
            canon_wallet_id_checked(wallet).map_err(|e| ErrorDetection::ValidationError {
                message: format!("ValidatorState::is_canonically_known invalid wallet: {e}"),
                tx_id: None,
            })?;

        Ok(self.inner.contains_key(&wallet_can))
    }

    // ─────────────────────────────────────────────────────────────
    // Persistent consensus latch: multi-validator era ever seen
    // ─────────────────────────────────────────────────────────────

    pub fn multi_validator_ever_seen(&self) -> Result<bool, ErrorDetection> {
        Self::db_get_multi_validator_ever_seen(&self.db_manager)
    }

    fn db_get_multi_validator_ever_seen(db: &RockDBManager) -> Result<bool, ErrorDetection> {
        let maybe_bytes = db.read(
            GlobalConfiguration::STATE_COLUMN_NAME,
            MULTI_VALIDATOR_EVER_SEEN_KEY,
        )?;

        Ok(maybe_bytes
            .as_deref()
            .map(|v| v.first().copied() == Some(b'1'))
            .unwrap_or(false))
    }

    fn db_set_multi_validator_ever_seen(db: &RockDBManager) -> Result<(), ErrorDetection> {
        db.write(
            GlobalConfiguration::STATE_COLUMN_NAME,
            MULTI_VALIDATOR_EVER_SEEN_KEY,
            b"1",
        )
        .map_err(|e| ErrorDetection::StorageError {
            message: format!("ValidatorState multi_validator_ever_seen write failed: {e}"),
        })
    }

    fn persist_multi_validator_latch_if_needed(&self) -> Result<(), ErrorDetection> {
        if self.inner.len() <= 1 {
            return Ok(());
        }

        if Self::db_get_multi_validator_ever_seen(&self.db_manager)? {
            return Ok(());
        }

        Self::db_set_multi_validator_ever_seen(&self.db_manager)
    }

    // ─────────────────────────────────────────────────────────────
    // Core mutation: applying RegisterNodeTx from blocks
    // ─────────────────────────────────────────────────────────────

    fn canonical_wallet_from_register_tx(reg: &RegisterNodeTx) -> Result<String, ErrorDetection> {
        let wallet_str = reg.wallet_str()?;
        canon_wallet_id_checked(wallet_str).map_err(|e| ErrorDetection::ValidationError {
            message: format!("ValidatorState::RegisterNodeTx wallet invalid: {e}"),
            tx_id: None,
        })
    }

    /// Extract replay-safe lifecycle event time from the containing block.
    fn canonical_event_timestamp_for_block(
        block: &Block,
        expected_height: u64,
    ) -> Result<u64, ErrorDetection> {
        if block.metadata.index != expected_height {
            return Err(validation_err(format!(
                "ValidatorState canonical event height mismatch: expected_height={} block.metadata.index={}",
                expected_height, block.metadata.index
            )));
        }

        TimePolicy::canonical_event_timestamp_from_block(
            "ValidatorState.block.metadata.timestamp",
            block.metadata.timestamp,
        )
    }

    fn upsert_register_into_map(
        map: &mut BTreeMap<String, ValidatorMeta>,
        height: u64,
        canonical_event_timestamp: u64,
        reg: &RegisterNodeTx,
    ) -> Result<bool, ErrorDetection> {
        let wallet_can = Self::canonical_wallet_from_register_tx(reg)?;

        let canonical_event_timestamp = TimePolicy::canonical_event_timestamp_from_block(
            "ValidatorState.register_or_renew.canonical_event_timestamp",
            canonical_event_timestamp,
        )?;

        let outcome = ValidatorLifecycle::apply_register_or_renew(
            map,
            &wallet_can,
            height,
            canonical_event_timestamp,
        )?;

        Ok(!matches!(outcome, RegisterOutcome::NoChange))
    }

    pub fn apply_block(
        &mut self,
        block: &Block,
        batch: &TransactionBatch,
    ) -> Result<(), ErrorDetection> {
        let height = block.metadata.index;
        let canonical_event_timestamp = Self::canonical_event_timestamp_for_block(block, height)?;
        let mut any_change = false;

        for kind in &batch.transactions {
            if let TxKind::RegisterNode(reg) = kind {
                let changed = Self::upsert_register_into_map(
                    &mut self.inner,
                    height,
                    canonical_event_timestamp,
                    reg,
                )?;
                any_change |= changed;
            }
        }

        if any_change {
            self.commit()?;
            self.persist_multi_validator_latch_if_needed()?;
        }

        Ok(())
    }

    /// Safe direct helper for callers that already have canonical block time.
    pub fn apply_register_tx_at_block_time(
        &mut self,
        block_height: u64,
        block_timestamp: u64,
        tx: &RegisterNodeTx,
    ) -> Result<(), ErrorDetection> {
        let canonical_event_timestamp = TimePolicy::canonical_event_timestamp_from_block(
            "ValidatorState.apply_register_tx_at_block_time.block_timestamp",
            block_timestamp,
        )?;

        let changed = Self::upsert_register_into_map(
            &mut self.inner,
            block_height,
            canonical_event_timestamp,
            tx,
        )?;

        if changed {
            self.commit()?;
            self.persist_multi_validator_latch_if_needed()?;
        }

        Ok(())
    }

    /// Backward-compatible helper retained for existing call sites.
    pub fn apply_register_tx(
        &mut self,
        block_height: u64,
        tx: &RegisterNodeTx,
    ) -> Result<(), ErrorDetection> {
        let block = self
            .db_manager
            .get_block_by_index(block_height)?
            .ok_or_else(|| ErrorDetection::NotFound {
                resource: format!(
                    "ValidatorState::apply_register_tx containing block at height {}",
                    block_height
                ),
            })?;

        let canonical_event_timestamp =
            Self::canonical_event_timestamp_for_block(&block, block_height)?;

        let changed = Self::upsert_register_into_map(
            &mut self.inner,
            block_height,
            canonical_event_timestamp,
            tx,
        )?;

        if changed {
            self.commit()?;
            self.persist_multi_validator_latch_if_needed()?;
        }

        Ok(())
    }

    fn lifecycle_config_with_activation_delay(
        activation_delay_blocks: u64,
    ) -> Result<ValidatorLifecycleConfig, ErrorDetection> {
        let mut cfg = ValidatorLifecycle::config();
        cfg.activation_delay_blocks = activation_delay_blocks;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Return the set of proposable validator wallet IDs at `height`,
    /// applying an explicit activation delay in blocks.
    ///
    /// IMPORTANT:
    /// - If `join_height == 0`, the validator is immediately proposable.
    /// - Otherwise: proposable when `height >= join_height + activation_delay_blocks`.
    ///
    /// Determinism:
    /// - Output is sorted.
    pub fn proposable_at(&self, height: u64, activation_delay_blocks: u64) -> Vec<String> {
        let cfg = match Self::lifecycle_config_with_activation_delay(activation_delay_blocks) {
            Ok(cfg) => cfg,
            Err(_) => return Vec::new(),
        };

        let mut v: Vec<String> = self
            .inner
            .iter()
            .filter_map(|(wallet, meta)| {
                if meta.is_proposable_at(height, cfg) {
                    Some(wallet.clone())
                } else {
                    None
                }
            })
            .collect();

        v.sort_unstable();
        v
    }

    // ─────────────────────────────────────────────────────────────
    // Chain replay / reorg support
    // ─────────────────────────────────────────────────────────────

    fn build_replay_map_from_chain(
        &self,
        tip: u64,
    ) -> Result<BTreeMap<String, ValidatorMeta>, ErrorDetection> {
        let mut map: BTreeMap<String, ValidatorMeta> = BTreeMap::new();

        // Canonical founder comes from block 0 only.
        // This is the only special-case bootstrap rule and it is replay-derived,
        // not local-state-derived.
        Self::seed_founder_from_canonical_genesis(&mut map, &self.db_manager)?;

        for idx in 0..=tip {
            let maybe_bytes = self.db_manager.get_tx_batch_bytes_by_index(idx)?;
            let bytes = match maybe_bytes {
                Some(b) => b,
                None => {
                    continue;
                }
            };

            // Guardrail: if a batch exists for this height, the corresponding
            // canonical block must also exist so lifecycle time is chain-derived.
            let block = self
                .db_manager
                .get_block_by_index(idx)?
                .ok_or_else(|| ErrorDetection::NotFound {
                    resource: format!(
                        "ValidatorState::build_replay_map_from_chain block at height {} for existing tx batch",
                        idx
                    ),
                })?;

            let canonical_event_timestamp = Self::canonical_event_timestamp_for_block(&block, idx)?;

            let batch = TransactionBatch::deserialize(&bytes).map_err(|e| {
                ErrorDetection::SerializationError {
                    details: format!(
                        "ValidatorState::build_replay_map_from_chain: failed to deserialize batch at height {}: {:?}",
                        idx, e
                    ),
                }
            })?;

            for kind in &batch.transactions {
                if let TxKind::RegisterNode(reg) = kind {
                    let _ = Self::upsert_register_into_map(
                        &mut map,
                        idx,
                        canonical_event_timestamp,
                        reg,
                    )?;
                }
            }
        }

        ValidatorLifecycle::validate_map(&map)?;
        Ok(map)
    }

    fn replace_with_rebuilt_map(
        &mut self,
        map: BTreeMap<String, ValidatorMeta>,
    ) -> Result<(), ErrorDetection> {
        ValidatorLifecycle::validate_map(&map)?;

        self.inner = map;
        self.commit()?;
        self.persist_multi_validator_latch_if_needed()?;

        Ok(())
    }

    pub fn rebuild_from_chain(&mut self, up_to_height: Option<u64>) -> Result<(), ErrorDetection> {
        let tip = match up_to_height {
            Some(h) => h,
            None => self.db_manager.get_tip_height()?,
        };

        let rebuilt = self.build_replay_map_from_chain(tip)?;

        self.replace_with_rebuilt_map(rebuilt)?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────
    // Query helpers
    // ─────────────────────────────────────────────────────────────

    pub fn all(&self) -> BTreeMap<String, ValidatorMeta> {
        self.inner.clone()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn meta_for(&self, wallet: &str) -> Option<ValidatorMeta> {
        let wallet_can = canon_wallet_id_checked(wallet).ok()?;
        self.inner.get(&wallet_can).cloned()
    }

    pub fn join_height(&self, wallet: &str) -> Option<u64> {
        self.meta_for(wallet).map(|m| m.join_height)
    }

    pub fn is_active_at(&self, wallet: &str, height: u64) -> bool {
        let Ok(wallet_can) = canon_wallet_id_checked(wallet) else {
            return false;
        };

        self.inner
            .get(&wallet_can)
            .is_some_and(|meta| ValidatorLifecycle::is_active_at(meta, height))
    }

    pub fn active_at(&self, height: u64) -> Vec<String> {
        ValidatorLifecycle::active_wallets_at(&self.inner, height).unwrap_or_default()
    }

    pub fn reward_eligible_at(&self, wallet: &str, at_height: u64) -> bool {
        let Ok(wallet_can) = canon_wallet_id_checked(wallet) else {
            return false;
        };

        self.inner
            .get(&wallet_can)
            .is_some_and(|meta| ValidatorLifecycle::reward_eligible_at(meta, at_height))
    }

    // ─────────────────────────────────────────────────────────────
    // Explicit exit hook (future tx wiring / tests / admin tools)
    // ─────────────────────────────────────────────────────────────

    /// Mark a validator as exited / deregistered at `height`.
    pub fn mark_exit(&mut self, wallet: &str, height: u64) -> Result<(), ErrorDetection> {
        let changed = ValidatorLifecycle::apply_exit(&mut self.inner, wallet, height)?;

        if changed {
            self.commit()?;
        }

        Ok(())
    }
}

#[inline]
fn validation_err(msg: impl Into<String>) -> ErrorDetection {
    ErrorDetection::ValidationError {
        message: msg.into(),
        tx_id: None,
    }
}
