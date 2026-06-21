use proptest::prelude::*;
use proptest::test_runner::{Config, FileFailurePersistence};

use fips204::ml_dsa_65;

use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::blockchain_001_builder::BlockchainBuilder;
use remzar::blockchain::mempool::MemPool;
use remzar::blockchain::transaction_001_tx::Transaction;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::consensus::por_000_ephemeral_registration::RegistryData;
use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_003_detection_system::DetectionSystem;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct BuilderCtx {
    builder: BlockchainBuilder,
    db: Arc<RockDBManager>,
    mempool: Arc<MemPool>,
    wallet: String,
    _root: PathBuf,
}

fn err_text<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn result_err_contains<T, E: core::fmt::Debug>(result: Result<T, E>, needle: &str) -> bool {
    match result {
        Ok(_) => false,
        Err(err) => err_text(err)
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase()),
    }
}

fn wallet_u64(seed: u64) -> String {
    format!("r{:0128x}", seed.saturating_add(1))
}

fn nonzero_hash(seed: u8) -> [u8; 64] {
    let fill = if seed == 0 { 1 } else { seed };
    [fill; 64]
}

fn unique_test_dir(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);

    let root = std::env::temp_dir().join(format!(
        "remzar_proptest_blockchain_001_builder_{label}_{}_{}",
        std::process::id(),
        id
    ));

    if root.exists() {
        let _ = std::fs::remove_dir_all(&root);
    }

    std::fs::create_dir_all(&root).expect("test root directory should be created");

    root
}

fn path_to_string(path: &Path) -> String {
    path.to_str()
        .expect("test path should be valid UTF-8")
        .to_owned()
}

fn new_signing_key() -> Arc<ml_dsa_65::PrivateKey> {
    let (_pk, sk) = ml_dsa_65::try_keygen().expect("ML-DSA-65 key generation should succeed");
    Arc::new(sk)
}

fn new_db(label: &str, wallet: &str) -> (Arc<RockDBManager>, PathBuf) {
    let root = unique_test_dir(label);
    let blockchain_dir = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);

    let opts = NodeOpts {
        data_dir: path_to_string(&root),
        identity_file: path_to_string(&root.join("identity.key")),
        wallet_address: wallet.to_owned(),
        ..NodeOpts::default()
    };

    let db = RockDBManager::new_blockchain(&opts, &path_to_string(&blockchain_dir))
        .expect("test blockchain RocksDB manager should initialize");

    db.set_latest_block_index(0)
        .expect("test db should set latest block index");
    db.set_tip_height(0).expect("test db should set tip height");

    (Arc::new(db), root)
}

fn new_builder_ctx_with_wallet(label: &str, wallet: String) -> BuilderCtx {
    let (db, root) = new_db(label, &wallet);

    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));

    let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000)));

    let signing_key = new_signing_key();

    let builder = BlockchainBuilder::new(
        Arc::clone(&db),
        Arc::clone(&mempool),
        wallet.clone(),
        tm,
        signing_key,
    )
    .expect("BlockchainBuilder::new should succeed for valid wallet");

    BuilderCtx {
        builder,
        db,
        mempool,
        wallet,
        _root: root,
    }
}

fn registry_from_wallets(wallets: &[String]) -> RegistryData {
    let mut registry = RegistryData::new();

    for (index, wallet) in wallets.iter().enumerate() {
        let height = u64::try_from(index).expect("test index should fit u64");

        registry
            .register_wallet_strict(wallet, height)
            .expect("test wallet should register in ephemeral registry");
    }

    registry
}

fn store_genesis_parent(ctx: &BuilderCtx) -> Block {
    let meta = BlockMetadata::new(
        0,
        1_700_000_000,
        [0u8; 64],
        nonzero_hash(9),
        [0u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    let block = Block::new(meta, None, ctx.wallet.clone(), 0)
        .expect("genesis parent block should construct");

    let bytes = block
        .serialize_for_storage()
        .expect("genesis parent should serialize");

    ctx.db
        .store_latest_block(&bytes, 0)
        .expect("genesis parent should store by index");

    ctx.db
        .index_block_by_hash(&block.block_hash, &bytes)
        .expect("genesis parent should index by hash");

    ctx.db
        .set_latest_block_index(0)
        .expect("latest block index should reset to genesis");

    ctx.db
        .set_tip_height(0)
        .expect("tip height should reset to genesis");

    block
}

fn seed_founder(ctx: &mut BuilderCtx) {
    ctx.builder
        .validator_state_mut()
        .seed_genesis_founder(&ctx.wallet, 1_700_000_000)
        .expect("founder should seed into canonical validator state");

    ctx.builder
        .set_registry(registry_from_wallets(std::slice::from_ref(&ctx.wallet)));

    prop_assert_can_live(ctx);
}

fn prop_assert_can_live(ctx: &BuilderCtx) {
    assert!(
        ctx.builder
            .consensus()
            .committee_eligibility()
            .is_wallet_live(&ctx.wallet),
        "local wallet must be live in runtime committee"
    );
}

fn make_transfer(seed: u64, index: usize, amount: u64) -> Transaction {
    let i = u64::try_from(index).expect("test index should fit u64");

    let sender = wallet_u64(seed.wrapping_add(i).wrapping_add(10_000));
    let receiver = wallet_u64(seed.wrapping_add(i).wrapping_add(20_000));

    Transaction::new(sender, receiver, amount.max(1))
        .expect("generated transfer should be structurally valid")
}

fn add_transfers_to_mempool(ctx: &BuilderCtx, seed: u64, count: usize, amount: u64) {
    for index in 0..count {
        let tx = make_transfer(seed, index, amount);

        ctx.mempool
            .add_transaction(&tx)
            .expect("generated transfer should add to mempool");
    }
}

fn batch_for_height(ctx: &BuilderCtx, height: u64) -> TransactionBatch {
    let bytes = ctx
        .db
        .get_batch_bytes_by_index(height)
        .expect("batch lookup should not fail")
        .expect("builder should persist transaction batch bytes");

    TransactionBatch::deserialize(&bytes).expect("persisted batch should deserialize")
}

fn count_transfer_txs(batch: &TransactionBatch) -> usize {
    batch
        .transactions
        .iter()
        .filter(|kind| matches!(kind, TxKind::Transfer(_)))
        .count()
}

fn block_bytes_for_height(ctx: &BuilderCtx, height: u64) -> Vec<u8> {
    ctx.db
        .get_block_bytes_by_index(height)
        .expect("block byte lookup should not fail")
        .expect("builder should persist block bytes")
}

proptest! {
    #![proptest_config(Config {
        cases: 10,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
        .. Config::default()
    })]

    // 001/25
    #[test]
    fn test_001_new_accepts_trimmed_valid_wallet_and_canonicalizes(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);
        let padded = format!(" \t{wallet}\n ");

        let ctx = new_builder_ctx_with_wallet(
            "new_accepts_trimmed_valid_wallet",
            padded,
        );

        prop_assert_eq!(
            ctx.builder.consensus().local_wallet(),
            &wallet,
            "builder consensus local wallet must be canonicalized"
        );

        prop_assert_eq!(
            ctx.builder.consensus().local_wallet().len(),
            129,
            "canonical Remzar wallet must stay r + 128 lowercase hex chars"
        );
    }

    // 002/25
    #[test]
    fn test_002_new_rejects_invalid_local_wallets(
        bad in "[A-Za-z0-9_./\\\\ -]{0,96}",
    ) {
        prop_assume!(!bad.starts_with('r') || bad.len() != 129);

        let fallback_wallet = wallet_u64(2);
        let (db, _root) = new_db("new_rejects_invalid_local_wallets", &fallback_wallet);

        let detection = Arc::new(DetectionSystem::new());
        let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
        let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(
            1_700_000_000,
        )));
        let signing_key = new_signing_key();

        let result = BlockchainBuilder::new(db, mempool, bad, tm, signing_key);

        prop_assert!(
            result.is_err(),
            "builder must reject malformed local wallet input"
        );
    }

    // 003/25
    #[test]
    fn test_003_consensus_and_consensus_mut_reference_same_local_wallet(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "consensus_and_consensus_mut_reference_same_local_wallet",
            wallet.clone(),
        );

        let immutable = ctx.builder.consensus().local_wallet().clone();
        let mutable = ctx.builder.consensus_mut().local_wallet().clone();

        prop_assert_eq!(
            &immutable,
            &wallet,
            "consensus() must expose the configured local wallet"
        );

        prop_assert_eq!(
            &mutable,
            &wallet,
            "consensus_mut() must expose the same configured local wallet"
        );
    }

    // 004/25
    #[test]
    fn test_004_set_registry_marks_local_wallet_live(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);
        let mut ctx = new_builder_ctx_with_wallet(
            "set_registry_marks_local_wallet_live",
            wallet.clone(),
        );

        ctx.builder
            .set_registry(registry_from_wallets(std::slice::from_ref(&wallet)));

        prop_assert!(
            ctx.builder
                .consensus()
                .committee_eligibility()
                .is_wallet_live(&wallet),
            "set_registry must mark local wallet live when registry contains it"
        );
    }

    // 005/25
    #[test]
    fn test_005_set_registry_replaces_old_live_wallets(
        old_seed in any::<u64>(),
        new_seed in any::<u64>(),
    ) {
        prop_assume!(old_seed != new_seed);

        let old_wallet = wallet_u64(old_seed);
        let new_wallet = wallet_u64(new_seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "set_registry_replaces_old_live_wallets",
            old_wallet.clone(),
        );

        ctx.builder
            .set_registry(registry_from_wallets(std::slice::from_ref(&old_wallet)));

        prop_assert!(
            ctx.builder
                .consensus()
                .committee_eligibility()
                .is_wallet_live(&old_wallet),
            "old wallet should be live before replacement"
        );

        ctx.builder
            .set_registry(registry_from_wallets(std::slice::from_ref(&new_wallet)));

        prop_assert!(
            !ctx.builder
                .consensus()
                .committee_eligibility()
                .is_wallet_live(&old_wallet),
            "set_registry must replace old runtime membership"
        );

        prop_assert!(
            ctx.builder
                .consensus()
                .committee_eligibility()
                .is_wallet_live(&new_wallet),
            "new registry wallet must become live"
        );
    }

    // 006/25
    #[test]
    fn test_006_pending_puzzle_proof_is_empty_on_new_builder(
        seed in any::<u64>(),
    ) {
        let ctx = new_builder_ctx_with_wallet(
            "pending_puzzle_proof_is_empty_on_new_builder",
            wallet_u64(seed),
        );

        prop_assert!(
            ctx.builder.pending_puzzle_proof().is_none(),
            "fresh builder must not start with a staged puzzle proof"
        );
    }

    // 007/25
    #[test]
    fn test_007_take_pending_puzzle_proof_empty_is_idempotent(
        seed in any::<u64>(),
    ) {
        let mut ctx = new_builder_ctx_with_wallet(
            "take_pending_puzzle_proof_empty_is_idempotent",
            wallet_u64(seed),
        );

        prop_assert!(
            ctx.builder.take_pending_puzzle_proof().is_none(),
            "taking missing proof should return None"
        );

        prop_assert!(
            ctx.builder.take_pending_puzzle_proof().is_none(),
            "taking missing proof repeatedly should remain None"
        );

        prop_assert!(
            ctx.builder.pending_puzzle_proof().is_none(),
            "taking missing proof must not create a proof"
        );
    }

    // 008/25
    #[test]
    fn test_008_heartbeat_keeps_builder_identity_stable(
        seed in any::<u64>(),
        count in 1usize..16usize,
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "heartbeat_keeps_builder_identity_stable",
            wallet.clone(),
        );

        for _ in 0..count {
            ctx.builder.heartbeat();
        }

        prop_assert_eq!(
            ctx.builder.consensus().local_wallet(),
            &wallet,
            "heartbeat must not mutate builder local wallet identity"
        );
    }

    // 009/25
    #[test]
    fn test_009_create_new_block_rejects_unsynced_before_any_parent_or_consensus_work(
        seed in any::<u64>(),
    ) {
        let mut ctx = new_builder_ctx_with_wallet(
            "create_new_block_rejects_unsynced",
            wallet_u64(seed),
        );

        let result = ctx.builder.create_new_block(false);

        prop_assert!(
            result_err_contains(result, "before full sync"),
            "builder must reject minting before full sync"
        );
    }

    // 010/25
    #[test]
    fn test_010_create_new_block_with_bypass_still_rejects_unsynced_first(
        seed in any::<u64>(),
    ) {
        let mut ctx = new_builder_ctx_with_wallet(
            "create_new_block_with_bypass_still_rejects_unsynced_first",
            wallet_u64(seed),
        );

        let result = ctx.builder.create_new_block_with_bypass(false, true);

        prop_assert!(
            result_err_contains(result, "before full sync"),
            "bypass_leader must not bypass the full-sync guard"
        );
    }

    // 011/25
    #[test]
    fn test_011_synced_mint_without_parent_block_fails_closed(
        seed in any::<u64>(),
    ) {
        let mut ctx = new_builder_ctx_with_wallet(
            "synced_mint_without_parent_block_fails_closed",
            wallet_u64(seed),
        );

        let result = ctx.builder.create_new_block(true);

        prop_assert!(
            result.is_err(),
            "synced mint without a stored parent block must fail closed"
        );

        prop_assert_eq!(
            ctx.db.get_tip_height().expect("tip read should succeed"),
            0,
            "failed mint must not advance tip height"
        );
    }

    // 012/25
    #[test]
    fn test_012_parent_exists_but_no_canonical_validator_fails_closed(
        seed in any::<u64>(),
    ) {
        let mut ctx = new_builder_ctx_with_wallet(
            "parent_exists_but_no_canonical_validator_fails_closed",
            wallet_u64(seed),
        );

        let _parent = store_genesis_parent(&ctx);

        let result = ctx.builder.create_new_block(true);

        prop_assert!(
            result.is_err(),
            "mint with parent but without canonical validator state must fail"
        );

        prop_assert_eq!(
            ctx.db.get_tip_height().expect("tip read should succeed"),
            0,
            "failed canonical-validator mint must not advance tip"
        );
    }

    // 013/25
    #[test]
    fn test_013_bypass_leader_is_rejected_even_after_parent_exists(
        seed in any::<u64>(),
    ) {
        let mut ctx = new_builder_ctx_with_wallet(
            "bypass_leader_is_rejected_even_after_parent_exists",
            wallet_u64(seed),
        );

        let _parent = store_genesis_parent(&ctx);

        let result = ctx.builder.create_new_block_with_bypass(true, true);

        prop_assert!(
            result.is_err(),
            "builder must not allow local tests/attackers to bypass canonical leader authorization"
        );

        prop_assert_eq!(
            ctx.db.get_tip_height().expect("tip read should succeed"),
            0,
            "rejected bypass mint must not advance tip"
        );
    }

    // 014/25
    #[test]
    fn test_014_runtime_rejoin_catchup_gate_blocks_synced_mint(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "runtime_rejoin_catchup_gate_blocks_synced_mint",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        ctx.builder
            .consensus_mut()
            .set_runtime_rejoin_catchup_gate(true, Some("property catchup gate".to_owned()));

        let result = ctx.builder.create_new_block(true);

        prop_assert!(
            result.is_err(),
            "runtime rejoin catchup gate must suppress minting"
        );

        prop_assert_eq!(
            ctx.db.get_tip_height().expect("tip read should succeed"),
            0,
            "catchup-gated mint must not advance tip"
        );
    }

    // 015/25
    #[test]
    fn test_015_runtime_branch_hydration_gate_blocks_synced_mint(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "runtime_branch_hydration_gate_blocks_synced_mint",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        ctx.builder
            .consensus_mut()
            .set_runtime_branch_hydration_active(true);

        let result = ctx.builder.create_new_block(true);

        prop_assert!(
            result.is_err(),
            "runtime branch hydration gate must suppress minting"
        );

        prop_assert_eq!(
            ctx.db.get_tip_height().expect("tip read should succeed"),
            0,
            "hydration-gated mint must not advance tip"
        );
    }

    // 016/25
    #[test]
    fn test_016_successful_empty_mint_advances_tip_and_latest_index_to_one(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "successful_empty_mint_advances_tip_and_latest_index_to_one",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        let block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1");

        prop_assert_eq!(
            block.metadata.index,
            1,
            "first non-genesis block must be height 1"
        );

        prop_assert_eq!(
            ctx.db.get_tip_height().expect("tip read should succeed"),
            1,
            "successful mint must advance tip height"
        );

        prop_assert_eq!(
            ctx.db.get_latest_block_index().expect("latest index read should succeed"),
            1,
            "successful mint must advance latest block index"
        );
    }

    // 017/25
    #[test]
    fn test_017_successful_mint_links_to_captured_genesis_parent_hash(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "successful_mint_links_to_captured_genesis_parent_hash",
            wallet,
        );

        let parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        let block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1");

        prop_assert_eq!(
            block.metadata.previous_hash,
            parent.block_hash,
            "builder must build on the exact captured parent hash"
        );

        prop_assert_ne!(
            block.metadata.previous_hash,
            [0u8; 64],
            "non-genesis block must not use zero previous hash"
        );
    }

    // 018/25
    #[test]
    fn test_018_successful_mint_sets_nonzero_guardian_signature_and_merkle_root(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "successful_mint_sets_nonzero_guardian_signature_and_merkle_root",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        let block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1");

        prop_assert_ne!(
            block.metadata.guardian_signature,
            [0u8; ml_dsa_65::SIG_LEN],
            "builder must attach a real nonzero guardian signature to non-genesis metadata"
        );

        prop_assert_ne!(
            block.metadata.merkle_root,
            [0u8; 64],
            "builder must attach a nonzero Merkle root"
        );
    }

    // 019/25
    #[test]
    fn test_019_committed_puzzle_proof_if_present_is_aligned_to_block_metadata(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "committed_puzzle_proof_if_present_is_aligned_to_block_metadata",
            wallet.clone(),
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        let block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1");

        if let Some(proof) = block.metadata.puzzle_proof.as_ref() {
            prop_assert_eq!(
                proof.height,
                block.metadata.index,
                "committed puzzle proof height must equal block height"
            );

            prop_assert_eq!(
                proof.prev_block_hash,
                block.metadata.previous_hash,
                "committed puzzle proof prev hash must equal block previous_hash"
            );

            prop_assert!(
                proof.validator.eq_ignore_ascii_case(&wallet),
                "committed puzzle proof validator must match local proposer"
            );
        }
    }

    // 020/25
    #[test]
    fn test_020_successful_mint_persists_block_by_index_and_hash(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "successful_mint_persists_block_by_index_and_hash",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        let block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1");

        let by_index = ctx
            .db
            .get_block_by_index(1)
            .expect("block by index lookup should not fail")
            .expect("block #1 must be present by index");

        let by_hash = ctx
            .db
            .get_block_by_hash(&block.block_hash)
            .expect("block must be present by hash");

        prop_assert_eq!(
            by_index.block_hash,
            block.block_hash,
            "indexed block must match returned minted block hash"
        );

        prop_assert_eq!(
            by_hash.block_hash,
            block.block_hash,
            "hash-indexed block must match returned minted block hash"
        );
    }

    // 021/25
    #[test]
    fn test_021_successful_mint_persists_deserializable_batch_for_height_one(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "successful_mint_persists_deserializable_batch_for_height_one",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        let _block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1");

        let batch = batch_for_height(&ctx, 1);

        prop_assert_eq!(
            batch.index,
            1,
            "persisted transaction batch must use same height as minted block"
        );

        prop_assert!(
            batch.timestamp >= 1_700_000_000,
            "builder-created batch timestamp should be realistic and nonnegative"
        );
    }

    // 022/25
    #[test]
    fn test_022_successful_mint_block_and_batch_bytes_fit_max_block_size(
        seed in any::<u64>(),
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "successful_mint_block_and_batch_bytes_fit_max_block_size",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        let _block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1");

        let block_bytes = block_bytes_for_height(&ctx, 1);

        let batch_bytes = ctx
            .db
            .get_batch_bytes_by_index(1)
            .expect("batch byte lookup should not fail")
            .expect("batch bytes should exist");

        let total = block_bytes.len().saturating_add(batch_bytes.len());

        prop_assert!(
            total <= usize::try_from(GlobalConfiguration::MAX_BLOCK_SIZE).unwrap_or(usize::MAX),
            "builder must only persist block+batch bytes within MAX_BLOCK_SIZE"
        );
    }

    // 023/25
    #[test]
    fn test_023_one_user_transfer_is_included_and_removed_from_mempool(
        seed in any::<u64>(),
        amount in 1u64..=1_000_000_000_000u64,
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "one_user_transfer_is_included_and_removed_from_mempool",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        add_transfers_to_mempool(&ctx, seed, 1, amount);

        prop_assert_eq!(
            ctx.mempool.mempool_size().expect("mempool size should read"),
            1,
            "test should start with one user transaction in mempool"
        );

        let _block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1 with transfer");

        let batch = batch_for_height(&ctx, 1);

        prop_assert_eq!(
            count_transfer_txs(&batch),
            1,
            "builder must include the one pending transfer transaction"
        );

        prop_assert_eq!(
            ctx.mempool.mempool_size().expect("mempool size should read"),
            0,
            "builder must remove included transfer from mempool after commit"
        );
    }

    // 024/25
    #[test]
    fn test_024_small_unique_user_transfer_set_is_included_and_removed(
        seed in any::<u64>(),
        amount in 1u64..=1_000_000_000u64,
        count in 1usize..8usize,
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "small_unique_user_transfer_set_is_included_and_removed",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        add_transfers_to_mempool(&ctx, seed, count, amount);

        prop_assert_eq!(
            ctx.mempool.mempool_size().expect("mempool size should read"),
            count,
            "test should start with generated transfers in mempool"
        );

        let _block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1 with small transfer set");

        let batch = batch_for_height(&ctx, 1);

        prop_assert_eq!(
            count_transfer_txs(&batch),
            count,
            "small generated transfer set should fit and be included exactly"
        );

        prop_assert_eq!(
            ctx.mempool.mempool_size().expect("mempool size should read"),
            0,
            "all included transfers must be removed from mempool"
        );
    }

    // 025/25
    #[test]
    fn test_025_minted_block_is_structurally_valid_and_storage_roundtrip_preserves_hash(
        seed in any::<u64>(),
        count in 0usize..6usize,
        amount in 1u64..=10_000_000u64,
    ) {
        let wallet = wallet_u64(seed);

        let mut ctx = new_builder_ctx_with_wallet(
            "minted_block_is_structurally_valid_and_storage_roundtrip_preserves_hash",
            wallet,
        );

        let _parent = store_genesis_parent(&ctx);
        seed_founder(&mut ctx);

        add_transfers_to_mempool(&ctx, seed, count, amount);

        let block = ctx
            .builder
            .create_new_block(true)
            .expect("seeded founder should mint block 1");

        block
            .metadata
            .validate_structural()
            .expect("builder-created non-genesis metadata must validate structurally");

        let stored = ctx
            .db
            .get_block_by_index(block.metadata.index)
            .expect("block index lookup should not fail")
            .expect("minted block should be stored by index");

        prop_assert_eq!(
            stored.block_hash,
            block.block_hash,
            "storage roundtrip must preserve minted block hash"
        );

        prop_assert_eq!(
            stored.metadata.index,
            block.metadata.index,
            "storage roundtrip must preserve minted block height"
        );

        prop_assert_eq!(
            stored.metadata.previous_hash,
            block.metadata.previous_hash,
            "storage roundtrip must preserve parent hash"
        );
    }
}
