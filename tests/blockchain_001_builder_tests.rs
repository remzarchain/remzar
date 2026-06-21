// tests/blockchain_001_builder_tests.rs

use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use remzar::blockchain::blockchain_001_builder::BlockchainBuilder;
use remzar::blockchain::genesis_001_block::GenesisBlock;
use remzar::blockchain::halving_schedule::RewardHalving;
use remzar::blockchain::mempool::MemPool;
use remzar::blockchain::validation::BlockchainValidation;
use remzar::consensus::por_000_ephemeral_registration::RegistryData;
use remzar::consensus::por_002_puzzle_engine::PorPuzzleEngine;
use remzar::consensus::por_004_puzzle_proof::PorPuzzleProof;
use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::alpha_003_detection_system::DetectionSystem;
use remzar::utility::hash_system_remzarhash::RemzarHash;
use remzar::utility::helper::{
    UNIT_DIVISOR, decode_hex_to_64, format_remzar, format_remzar_trim, to_micro_units_str,
};

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct BuilderCtx {
    builder: BlockchainBuilder,
    db: Arc<RockDBManager>,
    wallet: String,
}

fn mint_one_block(ctx: &mut BuilderCtx) -> Block {
    let block = match ctx.builder.create_new_block(true) {
        Ok(block) => block,
        Err(err) => panic!("create_new_block failed: {err:?}"),
    };

    ctx.builder
        .consensus_mut()
        .note_validator_state_rebuilt_to_tip(block.metadata.index);

    ctx.builder
        .consensus_mut()
        .set_runtime_canonical_tip_context(block.metadata.index, block.block_hash);

    ctx.builder
        .set_registry(must_registry(std::slice::from_ref(&ctx.wallet)));

    block
}

fn prepare_builder_with_parent_and_founder(name: &str) -> BuilderCtx {
    let mut ctx = must_ctx(name);

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }

    seed_founder(&mut ctx);

    assert!(
        ctx.builder
            .consensus()
            .committee_eligibility()
            .is_wallet_live(&ctx.wallet)
    );

    ctx
}

fn extra_builder_block_proof(
    height: u64,
    wallet: &str,
    prev_hash: [u8; 64],
    output: u128,
) -> BlockPuzzleProof {
    match BlockPuzzleProof::new(height, wallet.to_owned(), prev_hash, output) {
        Ok(proof) => proof,
        Err(err) => panic!("BlockPuzzleProof::new failed: {err:?}"),
    }
}

fn err_to_string<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn wallet_u64(seed: u64) -> String {
    format!("r{:0128x}", seed.saturating_add(1))
}

fn nonzero_hash(seed: u8) -> [u8; 64] {
    let fill = if seed == 0 { 1 } else { seed };
    [fill; 64]
}

fn nonzero_sig(seed: u8) -> [u8; ml_dsa_65::SIG_LEN] {
    let fill = if seed == 0 { 1 } else { seed };
    [fill; ml_dsa_65::SIG_LEN]
}

fn unique_test_dir(name: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "remzar_blockchain_01_001_builder_tests_{name}_{}_{}",
        std::process::id(),
        id
    ));

    if fs::remove_dir_all(&dir).is_err() {
        // Nothing to clean.
    }

    dir
}

fn path_to_string(path: &Path) -> Result<String, String> {
    match path.to_str() {
        Some(s) => Ok(s.to_owned()),
        None => Err(format!("path is not valid UTF-8: {}", path.display())),
    }
}

fn new_signing_key() -> Result<Arc<ml_dsa_65::PrivateKey>, String> {
    let (_pk, sk) =
        ml_dsa_65::try_keygen().map_err(|e| format!("ml_dsa_65::try_keygen failed: {e}"))?;
    Ok(Arc::new(sk))
}

fn new_db(name: &str, wallet: &str) -> Result<Arc<RockDBManager>, String> {
    let base_dir = unique_test_dir(name);
    let blockchain_dir = base_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);

    let opts = NodeOpts {
        data_dir: path_to_string(&base_dir)?,
        identity_file: path_to_string(&base_dir.join("identity.key"))?,
        wallet_address: wallet.to_owned(),
        ..NodeOpts::default()
    };

    let blockchain_dir_str = path_to_string(&blockchain_dir)?;
    let db_inner =
        RockDBManager::new_blockchain(&opts, &blockchain_dir_str).map_err(err_to_string)?;

    db_inner.set_latest_block_index(0).map_err(err_to_string)?;
    db_inner.set_tip_height(0).map_err(err_to_string)?;

    Ok(Arc::new(db_inner))
}

fn new_builder_ctx(name: &str) -> Result<BuilderCtx, String> {
    let wallet = wallet_u64(1);
    let db = new_db(name, &wallet)?;
    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000)));
    let signing_key = new_signing_key()?;

    let builder = BlockchainBuilder::new(Arc::clone(&db), mempool, wallet.clone(), tm, signing_key)
        .map_err(err_to_string)?;

    Ok(BuilderCtx {
        builder,
        db,
        wallet,
    })
}

fn must_ctx(name: &str) -> BuilderCtx {
    match new_builder_ctx(name) {
        Ok(ctx) => ctx,
        Err(err) => panic!("failed to create builder test context for {name}: {err}"),
    }
}

fn must_registry(wallets: &[String]) -> RegistryData {
    let mut reg = RegistryData::new();

    for (idx, wallet) in wallets.iter().enumerate() {
        let height = match u64::try_from(idx) {
            Ok(v) => v,
            Err(err) => panic!("index conversion failed: {err}"),
        };

        match reg.register_wallet_strict(wallet, height) {
            Ok(_registered) => {}
            Err(err) => panic!("failed to register wallet {wallet}: {err:?}"),
        }
    }

    reg
}

fn assert_result_err_contains<T, E: core::fmt::Debug>(result: Result<T, E>, needle: &str) {
    match result {
        Ok(_value) => panic!("expected error containing '{needle}', got Ok"),
        Err(err) => {
            let text = format!("{err:?}");
            let text_lower = text.to_ascii_lowercase();
            let needle_lower = needle.to_ascii_lowercase();

            assert!(
                text_lower.contains(&needle_lower),
                "expected error containing '{needle}', got: {text}"
            );
        }
    }
}

fn invalid_proof(
    height: u64,
    validator: String,
    prev_block_hash: [u8; 64],
    output: u128,
) -> PorPuzzleProof {
    PorPuzzleProof {
        height,
        validator,
        prev_block_hash,
        output,
    }
}

fn valid_unknown_parent_proof(
    wallet: &str,
    height: u64,
    prev_block_hash: [u8; 64],
) -> Result<PorPuzzleProof, String> {
    let engine = PorPuzzleEngine::from_globals();
    let header = engine.derive_puzzle(height, wallet, prev_block_hash);
    let solution = engine
        .solve_locally_checked(&header)
        .map_err(err_to_string)?;

    Ok(PorPuzzleProof::from_solution(&solution))
}

fn store_genesis_parent(ctx: &BuilderCtx) -> Result<Block, String> {
    let meta = BlockMetadata::new(
        0,
        1_700_000_000,
        [0u8; 64],
        nonzero_hash(9),
        [0u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    let block = Block::new(meta, None, ctx.wallet.clone(), 0).map_err(err_to_string)?;
    let bytes = block.serialize_for_storage().map_err(err_to_string)?;

    ctx.db
        .store_latest_block(&bytes, 0)
        .map_err(err_to_string)?;
    ctx.db
        .index_block_by_hash(&block.block_hash, &bytes)
        .map_err(err_to_string)?;
    ctx.db.set_latest_block_index(0).map_err(err_to_string)?;
    ctx.db.set_tip_height(0).map_err(err_to_string)?;

    Ok(block)
}

fn seed_founder(ctx: &mut BuilderCtx) {
    match ctx
        .builder
        .validator_state_mut()
        .seed_genesis_founder(&ctx.wallet, 1_700_000_000)
    {
        Ok(()) => {}
        Err(err) => panic!("seed_genesis_founder failed: {err:?}"),
    }

    ctx.builder
        .set_registry(must_registry(std::slice::from_ref(&ctx.wallet)));

    assert!(
        ctx.builder
            .consensus()
            .committee_eligibility()
            .is_wallet_live(&ctx.wallet)
    );
}

fn extra_builder_valid_metadata(index: u64) -> BlockMetadata {
    let previous_hash = if index == 0 {
        [0u8; 64]
    } else {
        nonzero_hash(41)
    };

    let guardian_signature = if index == 0 {
        [0u8; ml_dsa_65::SIG_LEN]
    } else {
        nonzero_sig(42)
    };

    BlockMetadata::new(
        index,
        1_700_000_000,
        previous_hash,
        nonzero_hash(43),
        guardian_signature,
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    )
}

fn extra_builder_make_parent_block(wallet: &str) -> Result<Block, String> {
    let meta = BlockMetadata::new(
        0,
        1_700_000_000,
        [0u8; 64],
        nonzero_hash(44),
        [0u8; ml_dsa_65::SIG_LEN],
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    Block::new(meta, None, wallet.to_owned(), 0).map_err(err_to_string)
}

fn extra_builder_store_existing_block(
    db: &RockDBManager,
    block: &Block,
    index: u64,
) -> Result<(), String> {
    let bytes = block.serialize_for_storage().map_err(err_to_string)?;

    db.store_latest_block(&bytes, index)
        .map_err(err_to_string)?;
    db.index_block_by_hash(&block.block_hash, &bytes)
        .map_err(err_to_string)?;
    db.set_latest_block_index(index).map_err(err_to_string)?;
    db.set_tip_height(index).map_err(err_to_string)?;

    Ok(())
}

#[test]
fn blockchain_01_001_builder_vector_new_initializes_local_wallet() {
    let ctx = must_ctx("vector_new_initializes_local_wallet");

    assert_eq!(
        ctx.builder.consensus().local_wallet().as_str(),
        ctx.wallet.as_str()
    );
    assert_eq!(ctx.builder.consensus().local_wallet().len(), 129);
}

#[test]
fn blockchain_02_001_builder_edge_new_rejects_invalid_local_wallet() {
    let wallet = wallet_u64(2);
    let db = match new_db("edge_new_rejects_invalid_local_wallet", &wallet) {
        Ok(db) => db,
        Err(err) => panic!("db setup failed: {err}"),
    };

    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000)));
    let signing_key = match new_signing_key() {
        Ok(sk) => sk,
        Err(err) => panic!("signing key setup failed: {err}"),
    };

    let result = BlockchainBuilder::new(db, mempool, "not-a-wallet".to_owned(), tm, signing_key);

    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchain_03_001_builder_vector_consensus_and_consensus_mut_reference_same_wallet() {
    let mut ctx = must_ctx("vector_consensus_and_consensus_mut_reference_same_wallet");

    let before = ctx.builder.consensus().local_wallet().clone();
    let after = ctx.builder.consensus_mut().local_wallet().clone();

    assert_eq!(before, ctx.wallet);
    assert_eq!(after, ctx.wallet);
}

#[test]
fn blockchain_04_001_builder_vector_validator_state_starts_without_unknown_wallet() {
    let ctx = must_ctx("vector_validator_state_starts_without_unknown_wallet");
    let unknown = wallet_u64(30);

    let known = match ctx.builder.validator_state().is_canonically_known(&unknown) {
        Ok(v) => v,
        Err(err) => panic!("is_canonically_known failed: {err:?}"),
    };

    assert!(!known);
}

#[test]
fn blockchain_05_001_builder_vector_validator_state_mut_seeds_founder() {
    let mut ctx = must_ctx("vector_validator_state_mut_seeds_founder");

    seed_founder(&mut ctx);

    let known = match ctx
        .builder
        .validator_state()
        .is_canonically_known(&ctx.wallet)
    {
        Ok(v) => v,
        Err(err) => panic!("is_canonically_known failed: {err:?}"),
    };

    assert!(known);
}

#[test]
fn blockchain_06_001_builder_vector_set_registry_marks_local_wallet_live() {
    let mut ctx = must_ctx("vector_set_registry_marks_local_wallet_live");

    ctx.builder
        .set_registry(must_registry(std::slice::from_ref(&ctx.wallet)));

    assert!(
        ctx.builder
            .consensus()
            .committee_eligibility()
            .is_wallet_live(&ctx.wallet)
    );
}

#[test]
fn blockchain_07_001_builder_edge_set_registry_replaces_old_live_wallets() {
    let mut ctx = must_ctx("edge_set_registry_replaces_old_live_wallets");
    let old_wallet = ctx.wallet.clone();
    let new_wallet = wallet_u64(6);

    ctx.builder
        .set_registry(must_registry(std::slice::from_ref(&old_wallet)));
    assert!(
        ctx.builder
            .consensus()
            .committee_eligibility()
            .is_wallet_live(&old_wallet)
    );

    ctx.builder
        .set_registry(must_registry(std::slice::from_ref(&new_wallet)));

    assert!(
        !ctx.builder
            .consensus()
            .committee_eligibility()
            .is_wallet_live(&old_wallet)
    );
    assert!(
        ctx.builder
            .consensus()
            .committee_eligibility()
            .is_wallet_live(&new_wallet)
    );
}

#[test]
fn blockchain_08_001_builder_vector_pending_puzzle_proof_empty_on_new_builder() {
    let ctx = must_ctx("vector_pending_puzzle_proof_empty_on_new_builder");

    assert!(ctx.builder.pending_puzzle_proof().is_none());
}

#[test]
fn blockchain_09_001_builder_vector_take_pending_puzzle_proof_empty_on_new_builder() {
    let mut ctx = must_ctx("vector_take_pending_puzzle_proof_empty_on_new_builder");

    assert!(ctx.builder.take_pending_puzzle_proof().is_none());
    assert!(ctx.builder.pending_puzzle_proof().is_none());
}

#[test]
fn blockchain_10_001_builder_vector_heartbeat_keeps_builder_usable() {
    let mut ctx = must_ctx("vector_heartbeat_keeps_builder_usable");

    ctx.builder.heartbeat();
    ctx.builder.heartbeat();

    assert_eq!(
        ctx.builder.consensus().local_wallet().as_str(),
        ctx.wallet.as_str()
    );
}

#[test]
fn blockchain_11_001_builder_edge_create_new_block_rejects_unsynced() {
    let mut ctx = must_ctx("edge_create_new_block_rejects_unsynced");

    let result = ctx.builder.create_new_block(false);

    assert_result_err_contains(result, "before full sync");
}

#[test]
fn blockchain_12_001_builder_edge_create_new_block_with_bypass_rejects_unsynced_first() {
    let mut ctx = must_ctx("edge_create_new_block_with_bypass_rejects_unsynced_first");

    let result = ctx.builder.create_new_block_with_bypass(false, true);

    assert_result_err_contains(result, "before full sync");
}

#[test]
fn blockchain_13_001_builder_edge_synced_mint_without_parent_block_fails_closed() {
    let mut ctx = must_ctx("edge_synced_mint_without_parent_block_fails_closed");

    let result = ctx.builder.create_new_block(true);

    assert_result_err_contains(result, "latest block");
}

#[test]
fn blockchain_14_001_builder_edge_synced_bypass_is_rejected_after_parent_exists() {
    let mut ctx = must_ctx("edge_synced_bypass_is_rejected_after_parent_exists");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }

    let result = ctx.builder.create_new_block_with_bypass(true, true);

    assert_result_err_contains(result, "bypass_leader");
}

#[test]
fn blockchain_15_001_builder_edge_parent_exists_but_no_canonical_validator_fails_closed() {
    let mut ctx = must_ctx("edge_parent_exists_but_no_canonical_validator_fails_closed");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }

    let result = ctx.builder.create_new_block(true);

    assert_result_err_contains(result, "canonical validators");
}

#[test]
fn blockchain_16_001_builder_vector_successfully_mints_empty_block_from_seeded_founder() {
    let mut ctx = must_ctx("vector_successfully_mints_empty_block_from_seeded_founder");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }
    seed_founder(&mut ctx);

    let block = match ctx.builder.create_new_block(true) {
        Ok(block) => block,
        Err(err) => panic!("create_new_block failed: {err:?}"),
    };

    assert_eq!(block.metadata.index, 1);
    assert_eq!(block.miner_wallet(), ctx.wallet.as_str());
    assert_ne!(block.block_hash, [0u8; 64]);
}

#[test]
fn blockchain_17_001_builder_vector_successful_mint_persists_tip_height() {
    let mut ctx = must_ctx("vector_successful_mint_persists_tip_height");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }
    seed_founder(&mut ctx);

    match ctx.builder.create_new_block(true) {
        Ok(_block) => {}
        Err(err) => panic!("create_new_block failed: {err:?}"),
    }

    let tip = match ctx.db.get_tip_height() {
        Ok(tip) => tip,
        Err(err) => panic!("get_tip_height failed: {err:?}"),
    };

    assert_eq!(tip, 1);
}

#[test]
fn blockchain_18_001_builder_vector_successful_mint_commits_puzzle_proof() {
    let mut ctx = must_ctx("vector_successful_mint_commits_puzzle_proof");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }
    seed_founder(&mut ctx);

    let block = match ctx.builder.create_new_block(true) {
        Ok(block) => block,
        Err(err) => panic!("create_new_block failed: {err:?}"),
    };

    let proof = match block.metadata.puzzle_proof.as_ref() {
        Some(proof) => proof,
        None => panic!("expected committed puzzle proof"),
    };

    assert_eq!(proof.height, 1);
    assert_eq!(proof.validator, ctx.wallet);
    assert_eq!(proof.prev_block_hash, block.metadata.previous_hash);
    assert_ne!(proof.output, 0);
}

#[test]
fn blockchain_19_001_builder_vector_successful_mint_persists_batch_bytes() {
    let mut ctx = must_ctx("vector_successful_mint_persists_batch_bytes");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }
    seed_founder(&mut ctx);

    match ctx.builder.create_new_block(true) {
        Ok(_block) => {}
        Err(err) => panic!("create_new_block failed: {err:?}"),
    }

    let batch = match ctx.db.get_tx_batch_bytes_by_index(1) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => panic!("expected tx batch bytes for height 1"),
        Err(err) => panic!("get_tx_batch_bytes_by_index failed: {err:?}"),
    };

    assert!(!batch.is_empty());
}

#[test]
fn blockchain_20_001_builder_adversarial_rejects_genesis_height_gossip_proof() {
    let mut ctx = must_ctx("adversarial_rejects_genesis_height_gossip_proof");
    let proof = invalid_proof(0, ctx.wallet.clone(), nonzero_hash(19), 1);

    assert!(!ctx.builder.on_puzzle_proof(&proof));
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        0
    );
}

#[test]
fn blockchain_21_001_builder_adversarial_rejects_noncanonical_gossip_wallet() {
    let mut ctx = must_ctx("adversarial_rejects_noncanonical_gossip_wallet");
    let proof = invalid_proof(1, "bad-wallet".to_owned(), nonzero_hash(20), 1);

    assert!(!ctx.builder.on_puzzle_proof(&proof));
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        0
    );
}

#[test]
fn blockchain_22_001_builder_adversarial_rejects_zero_parent_hash_gossip_proof() {
    let mut ctx = must_ctx("adversarial_rejects_zero_parent_hash_gossip_proof");
    let proof = invalid_proof(1, ctx.wallet.clone(), [0u8; 64], 1);

    assert!(!ctx.builder.on_puzzle_proof(&proof));
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        0
    );
}

#[test]
fn blockchain_23_001_builder_adversarial_rejects_zero_output_gossip_proof() {
    let mut ctx = must_ctx("adversarial_rejects_zero_output_gossip_proof");
    let proof = invalid_proof(1, ctx.wallet.clone(), nonzero_hash(22), 0);

    assert!(!ctx.builder.on_puzzle_proof(&proof));
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        0
    );
}

#[test]
fn blockchain_24_001_builder_adversarial_valid_unknown_parent_gossip_proof_buffers() {
    let mut ctx = must_ctx("adversarial_valid_unknown_parent_gossip_proof_buffers");
    let parent = nonzero_hash(23);

    let proof = match valid_unknown_parent_proof(&ctx.wallet, 23, parent) {
        Ok(proof) => proof,
        Err(err) => panic!("failed to create valid proof: {err}"),
    };

    assert!(ctx.builder.on_puzzle_proof(&proof));
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        1
    );
}

#[test]
fn blockchain_25_001_builder_adversarial_duplicate_unknown_parent_gossip_proof_deduplicates() {
    let mut ctx = must_ctx("adversarial_duplicate_unknown_parent_gossip_proof_deduplicates");
    let parent = nonzero_hash(24);

    let proof = match valid_unknown_parent_proof(&ctx.wallet, 24, parent) {
        Ok(proof) => proof,
        Err(err) => panic!("failed to create valid proof: {err}"),
    };

    assert!(ctx.builder.on_puzzle_proof(&proof));
    assert!(ctx.builder.on_puzzle_proof(&proof));

    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        1
    );
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        1
    );
}

#[test]
fn blockchain_26_001_builder_vector_remote_gossip_proof_does_not_stage_local_pending_proof() {
    let mut ctx = must_ctx("vector_remote_gossip_proof_does_not_stage_local_pending_proof");
    let parent = nonzero_hash(25);

    let proof = match valid_unknown_parent_proof(&ctx.wallet, 25, parent) {
        Ok(proof) => proof,
        Err(err) => panic!("failed to create valid proof: {err}"),
    };

    assert!(ctx.builder.on_puzzle_proof(&proof));
    assert!(ctx.builder.pending_puzzle_proof().is_none());
    assert!(ctx.builder.take_pending_puzzle_proof().is_none());
}

#[test]
fn blockchain_27_001_builder_vector_consensus_mut_gc_removes_old_buffered_gossip_proof() {
    let mut ctx = must_ctx("vector_consensus_mut_gc_removes_old_buffered_gossip_proof");
    let parent = nonzero_hash(26);

    let proof = match valid_unknown_parent_proof(&ctx.wallet, 26, parent) {
        Ok(proof) => proof,
        Err(err) => panic!("failed to create valid proof: {err}"),
    };

    assert!(ctx.builder.on_puzzle_proof(&proof));
    ctx.builder.consensus_mut().gc_puzzle_pool_below(27);

    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        0
    );
}

#[test]
fn blockchain_28_001_builder_edge_runtime_catchup_gate_toggles_through_consensus_mut() {
    let mut ctx = must_ctx("edge_runtime_catchup_gate_toggles_through_consensus_mut");

    ctx.builder
        .consensus_mut()
        .set_runtime_rejoin_catchup_gate(true, Some("test catchup".to_owned()));
    assert!(ctx.builder.consensus().runtime_rejoin_catchup_gate_active());

    ctx.builder
        .consensus_mut()
        .set_runtime_rejoin_catchup_gate(false, None);
    assert!(!ctx.builder.consensus().runtime_rejoin_catchup_gate_active());
}

#[test]
fn blockchain_29_001_builder_edge_branch_hydration_gate_toggles_through_consensus_mut() {
    let mut ctx = must_ctx("edge_branch_hydration_gate_toggles_through_consensus_mut");

    ctx.builder
        .consensus_mut()
        .set_runtime_branch_hydration_active(true);
    assert!(ctx.builder.consensus().runtime_branch_hydration_active());

    ctx.builder
        .consensus_mut()
        .set_runtime_branch_hydration_active(false);
    assert!(!ctx.builder.consensus().runtime_branch_hydration_active());
}

#[test]
fn blockchain_30_001_builder_property_runtime_registry_collects_sorted_register_txs() {
    let mut ctx = must_ctx("property_runtime_registry_collects_sorted_register_txs");

    let w3 = wallet_u64(103);
    let w1 = wallet_u64(101);
    let w2 = wallet_u64(102);

    ctx.builder
        .set_registry(must_registry(&[w3.clone(), w1.clone(), w2.clone()]));

    let txs = ctx
        .builder
        .consensus()
        .collect_register_node_txs_for_block(1);

    let wallets = txs
        .iter()
        .map(|tx| match tx.wallet_str() {
            Ok(wallet) => wallet.to_owned(),
            Err(err) => panic!("wallet_str failed: {err:?}"),
        })
        .collect::<Vec<_>>();

    assert_eq!(wallets, vec![w1, w2, w3]);
}

#[test]
fn blockchain_31_001_builder_edge_canonical_founder_is_not_re_registered() {
    let mut ctx = must_ctx("edge_canonical_founder_is_not_re_registered");

    seed_founder(&mut ctx);
    ctx.builder
        .set_registry(must_registry(std::slice::from_ref(&ctx.wallet)));

    let txs = ctx
        .builder
        .consensus()
        .collect_register_node_txs_for_block(1);

    assert!(txs.is_empty());
}

#[test]
fn blockchain_32_001_builder_vector_reward_eligibility_false_for_unknown_wallet() {
    let ctx = must_ctx("vector_reward_eligibility_false_for_unknown_wallet");
    let unknown = wallet_u64(31);

    assert!(!ctx.builder.consensus().reward_eligible_at(&unknown, 100));
}

#[test]
fn blockchain_33_001_builder_vector_reward_eligibility_true_for_seeded_founder() {
    let mut ctx = must_ctx("vector_reward_eligibility_true_for_seeded_founder");

    seed_founder(&mut ctx);

    assert!(ctx.builder.consensus().reward_eligible_at(&ctx.wallet, 100));
}

#[test]
fn blockchain_34_001_builder_vector_successful_mint_leaves_local_proof_available_for_gossip() {
    let mut ctx = must_ctx("vector_successful_mint_leaves_local_proof_available_for_gossip");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }
    seed_founder(&mut ctx);

    match ctx.builder.create_new_block(true) {
        Ok(_block) => {}
        Err(err) => panic!("create_new_block failed: {err:?}"),
    }

    let proof = match ctx.builder.pending_puzzle_proof() {
        Some(proof) => proof,
        None => panic!("expected staged proof after successful mint"),
    };

    assert_eq!(proof.height, 1);
    assert_eq!(proof.validator, ctx.wallet);
}

#[test]
fn blockchain_35_001_builder_vector_take_pending_proof_after_success_clears_it() {
    let mut ctx = must_ctx("vector_take_pending_proof_after_success_clears_it");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }
    seed_founder(&mut ctx);

    match ctx.builder.create_new_block(true) {
        Ok(_block) => {}
        Err(err) => panic!("create_new_block failed: {err:?}"),
    }

    let proof = ctx.builder.take_pending_puzzle_proof();
    assert!(proof.is_some());
    assert!(ctx.builder.pending_puzzle_proof().is_none());
    assert!(ctx.builder.take_pending_puzzle_proof().is_none());
}

#[test]
fn blockchain_36_001_builder_adversarial_tampered_valid_shape_gossip_proof_is_rejected() {
    let mut ctx = must_ctx("adversarial_tampered_valid_shape_gossip_proof_is_rejected");
    let parent = nonzero_hash(35);

    let mut proof = match valid_unknown_parent_proof(&ctx.wallet, 35, parent) {
        Ok(proof) => proof,
        Err(err) => panic!("failed to create valid proof: {err}"),
    };
    proof.output = proof.output.saturating_add(1);

    assert!(!ctx.builder.on_puzzle_proof(&proof));
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        0
    );
}

#[test]
fn blockchain_37_001_builder_fuzz_invalid_gossip_proof_shapes_are_rejected() {
    let mut ctx = must_ctx("fuzz_invalid_gossip_proof_shapes_are_rejected");

    let cases = vec![
        invalid_proof(0, ctx.wallet.clone(), nonzero_hash(36), 1),
        invalid_proof(1, "bad-wallet".to_owned(), nonzero_hash(36), 1),
        invalid_proof(1, ctx.wallet.clone(), [0u8; 64], 1),
        invalid_proof(1, ctx.wallet.clone(), [0xFFu8; 64], 1),
        invalid_proof(1, ctx.wallet.clone(), nonzero_hash(36), 0),
        invalid_proof(10_000_001, ctx.wallet.clone(), nonzero_hash(36), 1),
    ];

    for proof in &cases {
        assert!(!ctx.builder.on_puzzle_proof(proof));
    }

    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        0
    );
}

#[test]
fn blockchain_38_001_builder_load_registry_sixty_four_wallets_collects_sixty_four_txs() {
    let mut ctx = must_ctx("load_registry_sixty_four_wallets_collects_sixty_four_txs");

    let wallets = (0u64..64u64).map(wallet_u64).collect::<Vec<_>>();
    ctx.builder.set_registry(must_registry(&wallets));

    let txs = ctx
        .builder
        .consensus()
        .collect_register_node_txs_for_block(1);

    assert_eq!(txs.len(), wallets.len());
}

#[test]
fn blockchain_39_001_builder_load_many_isolated_builders_initialize_cleanly() {
    for i in 0u64..8u64 {
        let name = format!("load_many_isolated_builders_initialize_cleanly_{i}");
        let ctx = must_ctx(&name);

        assert_eq!(
            ctx.builder.consensus().local_wallet().as_str(),
            ctx.wallet.as_str()
        );
        assert!(ctx.builder.pending_puzzle_proof().is_none());
    }
}

#[test]
fn blockchain_40_001_builder_property_successful_mint_stores_block_by_index_and_hash() {
    let mut ctx = must_ctx("property_successful_mint_stores_block_by_index_and_hash");

    match store_genesis_parent(&ctx) {
        Ok(_block) => {}
        Err(err) => panic!("failed to store genesis parent: {err}"),
    }
    seed_founder(&mut ctx);

    let minted = match ctx.builder.create_new_block(true) {
        Ok(block) => block,
        Err(err) => panic!("create_new_block failed: {err:?}"),
    };

    let by_index = match ctx.db.get_block_by_index(1) {
        Ok(Some(block)) => block,
        Ok(None) => panic!("expected block at index 1"),
        Err(err) => panic!("get_block_by_index failed: {err:?}"),
    };

    let by_hash = match ctx.db.get_block_by_hash(&minted.block_hash) {
        Some(block) => block,
        None => panic!("expected block by hash"),
    };

    assert_eq!(by_index.block_hash, minted.block_hash);
    assert_eq!(by_hash.block_hash, minted.block_hash);
}

#[test]
fn blockchain_41_001_builder_vector_remzarhash_bytes_hash_is_64_bytes() {
    let hash = RemzarHash::compute_bytes_hash(b"builder-connection-vector");

    assert_eq!(hash.len(), 64);
    assert_ne!(hash, [0u8; 64]);
}

#[test]
fn blockchain_42_001_builder_vector_remzarhash_hex_is_128_lower_hex_chars() {
    let hex_hash = RemzarHash::compute_bytes_hash_hex(b"builder-connection-hex");

    assert_eq!(hex_hash.len(), 128);
    assert!(
        hex_hash
            .as_bytes()
            .iter()
            .all(|b| matches!(*b, b'0'..=b'9' | b'a'..=b'f'))
    );
}

#[test]
fn blockchain_43_001_builder_property_remzarhash_changes_when_input_changes() {
    let first = RemzarHash::compute_bytes_hash(b"builder-input-a");
    let second = RemzarHash::compute_bytes_hash(b"builder-input-b");

    assert_ne!(first, second);
}

#[test]
fn blockchain_44_001_builder_vector_remzarhash_compute_data_hash_for_metadata() {
    let meta = extra_builder_valid_metadata(1);

    let hash = match RemzarHash::compute_data_hash(&meta) {
        Ok(hash) => hash,
        Err(err) => panic!("compute_data_hash failed: {err:?}"),
    };

    assert_eq!(hash.len(), 128);
}

#[test]
fn blockchain_45_001_builder_property_remzarhash_verify_data_hash_accepts_exact_hash() {
    let meta = extra_builder_valid_metadata(1);

    let hash = match RemzarHash::compute_data_hash(&meta) {
        Ok(hash) => hash,
        Err(err) => panic!("compute_data_hash failed: {err:?}"),
    };

    let verified = match RemzarHash::verify_data_hash(&meta, &hash) {
        Ok(v) => v,
        Err(err) => panic!("verify_data_hash failed: {err:?}"),
    };

    assert!(verified);
}

#[test]
fn blockchain_46_001_builder_edge_remzarhash_verify_data_hash_rejects_short_hex() {
    let meta = extra_builder_valid_metadata(1);

    let result = RemzarHash::verify_data_hash(&meta, "abcd");

    assert_result_err_contains(result, "expected hex length");
}

#[test]
fn blockchain_47_001_builder_edge_remzarhash_compute_data_hash_batch_rejects_empty_batch() {
    let empty: Vec<BlockMetadata> = Vec::new();

    let result = RemzarHash::compute_data_hash_batch(&empty);

    assert_result_err_contains(result, "at least one item");
}

#[test]
fn blockchain_48_001_builder_vector_remzarhash_truncated_hash_is_16_hex_chars() {
    let meta = extra_builder_valid_metadata(1);

    let hash = match RemzarHash::compute_truncated_hash(&meta) {
        Ok(hash) => hash,
        Err(err) => panic!("compute_truncated_hash failed: {err:?}"),
    };

    assert_eq!(hash.len(), 16);
}

#[test]
fn blockchain_49_001_builder_property_remzarhash_verify_truncated_hash_accepts_exact_hash() {
    let meta = extra_builder_valid_metadata(1);

    let hash = match RemzarHash::compute_truncated_hash(&meta) {
        Ok(hash) => hash,
        Err(err) => panic!("compute_truncated_hash failed: {err:?}"),
    };

    let verified = match RemzarHash::verify_truncated_hash(&meta, &hash) {
        Ok(v) => v,
        Err(err) => panic!("verify_truncated_hash failed: {err:?}"),
    };

    assert!(verified);
}

#[test]
fn blockchain_50_001_builder_edge_remzarhash_verify_truncated_hash_rejects_wrong_length() {
    let meta = extra_builder_valid_metadata(1);

    let result = RemzarHash::verify_truncated_hash(&meta, "abc");

    assert_result_err_contains(result, "expected hex length");
}

#[test]
fn blockchain_51_001_builder_vector_metadata_without_puzzle_proof_has_zero_commitment() {
    let meta = extra_builder_valid_metadata(1);

    let commitment = match meta.puzzle_commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("puzzle_commitment_bytes failed: {err:?}"),
    };

    assert_eq!(commitment, [0u8; 64]);
}

#[test]
fn blockchain_52_001_builder_vector_metadata_without_puzzle_proof_hex_is_128_zero_chars() {
    let meta = extra_builder_valid_metadata(1);

    let hex = match meta.puzzle_commitment_hex() {
        Ok(hex) => hex,
        Err(err) => panic!("puzzle_commitment_hex failed: {err:?}"),
    };

    assert_eq!(hex.len(), 128);
    assert_eq!(hex, "0".repeat(128));
}

#[test]
fn blockchain_53_001_builder_vector_metadata_set_merkle_root_empty_uses_dummy_root() {
    let mut meta = extra_builder_valid_metadata(1);

    let empty: Vec<u8> = Vec::new();
    match meta.set_merkle_root(&empty) {
        Ok(()) => {}
        Err(err) => panic!("set_merkle_root failed: {err:?}"),
    }

    assert_ne!(meta.merkle_root, [0u8; 64]);
    assert_ne!(meta.merkle_root, meta.previous_hash);
}

#[test]
fn blockchain_54_001_builder_property_metadata_compute_hash_is_stable() {
    let meta = extra_builder_valid_metadata(1);

    let first = match meta.compute_hash() {
        Ok(hash) => hash,
        Err(err) => panic!("first compute_hash failed: {err:?}"),
    };
    let second = match meta.compute_hash() {
        Ok(hash) => hash,
        Err(err) => panic!("second compute_hash failed: {err:?}"),
    };

    assert_eq!(first, second);
    assert_eq!(first.len(), 128);
}

#[test]
fn blockchain_55_001_builder_property_metadata_verify_hash_accepts_own_hash() {
    let meta = extra_builder_valid_metadata(1);

    let hash = match meta.compute_hash() {
        Ok(hash) => hash,
        Err(err) => panic!("compute_hash failed: {err:?}"),
    };

    let verified = match meta.verify_hash(&hash) {
        Ok(v) => v,
        Err(err) => panic!("verify_hash failed: {err:?}"),
    };

    assert!(verified);
}

#[test]
fn blockchain_56_001_builder_edge_metadata_verify_hash_rejects_short_hash() {
    let meta = extra_builder_valid_metadata(1);

    let result = meta.verify_hash("abcd");

    assert_result_err_contains(result, "hash hex length");
}

#[test]
fn blockchain_57_001_builder_vector_metadata_to_bytes_from_bytes_roundtrip() {
    let meta = extra_builder_valid_metadata(1);

    let bytes = match meta.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("to_bytes failed: {err:?}"),
    };

    let decoded = match BlockMetadata::from_bytes(&bytes) {
        Ok(meta) => meta,
        Err(err) => panic!("from_bytes failed: {err:?}"),
    };

    assert_eq!(decoded, meta);
}

#[test]
fn blockchain_58_001_builder_fuzz_metadata_from_bytes_rejects_garbage_payloads() {
    let payloads = vec![Vec::new(), vec![0], vec![1, 2, 3, 4], vec![255; 64]];

    for payload in &payloads {
        let result = BlockMetadata::from_bytes(payload);
        assert!(result.is_err());
    }
}

#[test]
fn blockchain_59_001_builder_edge_metadata_validate_rejects_too_small_size() {
    let mut meta = extra_builder_valid_metadata(1);
    meta.size = 1;

    let result = meta.validate_structural();

    assert_result_err_contains(result, "size");
}

#[test]
fn blockchain_60_001_builder_edge_metadata_validate_rejects_too_old_timestamp() {
    let mut meta = extra_builder_valid_metadata(1);
    meta.timestamp = 1;

    let result = meta.validate_structural();

    assert_result_err_contains(result, "timestamp");
}

#[test]
fn blockchain_61_001_builder_edge_metadata_validate_rejects_non_genesis_zero_previous_hash() {
    let mut meta = extra_builder_valid_metadata(1);
    meta.previous_hash = [0u8; 64];

    let result = meta.validate_structural();

    assert_result_err_contains(result, "previous_hash");
}

#[test]
fn blockchain_62_001_builder_edge_metadata_validate_rejects_zero_merkle_root() {
    let mut meta = extra_builder_valid_metadata(1);
    meta.merkle_root = [0u8; 64];

    let result = meta.validate_structural();

    assert_result_err_contains(result, "merkle");
}

#[test]
fn blockchain_63_001_builder_edge_validation_rejects_ff_previous_hash() {
    let mut meta = extra_builder_valid_metadata(1);
    meta.previous_hash = [0xFFu8; 64];

    let detection = DetectionSystem::new();
    let result = BlockchainValidation::validate_block_metadata(&meta, &detection);

    assert_result_err_contains(result, "previous_hash");
}

#[test]
fn blockchain_64_001_builder_edge_block_new_rejects_non_genesis_empty_miner() {
    let meta = extra_builder_valid_metadata(1);

    let result = Block::new(meta, None, String::new(), 0);

    assert_result_err_contains(result, "miner");
}

#[test]
fn blockchain_65_001_builder_vector_block_new_accepts_genesis_empty_miner() {
    let meta = extra_builder_valid_metadata(0);

    let block = match Block::new(meta, None, String::new(), 0) {
        Ok(block) => block,
        Err(err) => panic!("Block::new genesis failed: {err:?}"),
    };

    assert_eq!(block.metadata.index, 0);
    assert_eq!(block.miner_wallet(), "");
    assert_ne!(block.block_hash, [0u8; 64]);
}

#[test]
fn blockchain_66_001_builder_edge_block_new_rejects_overlong_batch_key() {
    let meta = extra_builder_valid_metadata(1);
    let overlong = "x".repeat(4097);

    let result = Block::new(meta, Some(overlong), wallet_u64(66), 0);

    assert_result_err_contains(result, "batch_key");
}

#[test]
fn blockchain_67_001_builder_property_block_verify_hash_accepts_fresh_block() {
    let meta = extra_builder_valid_metadata(1);

    let block = match Block::new(
        meta,
        Some("tx_batch_0000000001".to_owned()),
        wallet_u64(67),
        0,
    ) {
        Ok(block) => block,
        Err(err) => panic!("Block::new failed: {err:?}"),
    };

    let verified = match block.verify_block_hash() {
        Ok(v) => v,
        Err(err) => panic!("verify_block_hash failed: {err:?}"),
    };

    assert!(verified);
}

#[test]
fn blockchain_68_001_builder_vector_block_storage_roundtrip_preserves_hash_and_miner() {
    let wallet = wallet_u64(68);
    let meta = extra_builder_valid_metadata(1);

    let block = match Block::new(
        meta,
        Some("tx_batch_0000000001".to_owned()),
        wallet.clone(),
        0,
    ) {
        Ok(block) => block,
        Err(err) => panic!("Block::new failed: {err:?}"),
    };

    let bytes = match block.serialize_for_storage() {
        Ok(bytes) => bytes,
        Err(err) => panic!("serialize_for_storage failed: {err:?}"),
    };

    let decoded = match Block::deserialize_from_storage(&bytes) {
        Ok(block) => block,
        Err(err) => panic!("deserialize_from_storage failed: {err:?}"),
    };

    assert_eq!(decoded.block_hash, block.block_hash);
    assert_eq!(decoded.miner_wallet(), wallet.as_str());
}

#[test]
fn blockchain_69_001_builder_edge_block_deserialize_rejects_too_short_payload() {
    let result = Block::deserialize_from_storage(&[1, 2, 3, 4]);

    assert_result_err_contains(result, "too short");
}

#[test]
fn blockchain_70_001_builder_vector_block_deserialize_accepts_legacy_zero_padding() {
    let meta = extra_builder_valid_metadata(1);
    let block = match Block::new(
        meta,
        Some("tx_batch_0000000001".to_owned()),
        wallet_u64(70),
        0,
    ) {
        Ok(block) => block,
        Err(err) => panic!("Block::new failed: {err:?}"),
    };

    let mut bytes = match block.serialize_for_storage() {
        Ok(bytes) => bytes,
        Err(err) => panic!("serialize_for_storage failed: {err:?}"),
    };
    bytes.extend_from_slice(&[0u8; 32]);

    let decoded = match Block::deserialize_from_storage(&bytes) {
        Ok(block) => block,
        Err(err) => panic!("padded deserialize_from_storage failed: {err:?}"),
    };

    assert_eq!(decoded.block_hash, block.block_hash);
}

#[test]
fn blockchain_71_001_builder_edge_genesis_new_rejects_empty_data() {
    let result = GenesisBlock::new_with_timestamp("", 1_700_000_000);

    assert_result_err_contains(result, "data");
}

#[test]
fn blockchain_72_001_builder_edge_genesis_new_rejects_oversized_data() {
    let oversized = "x".repeat(1025);
    let result = GenesisBlock::new_with_timestamp(&oversized, 1_700_000_000);

    assert_result_err_contains(result, "too large");
}

#[test]
fn blockchain_73_001_builder_vector_genesis_new_without_miner_has_no_founder() {
    let genesis = match GenesisBlock::new_with_timestamp("remzar genesis", 1_700_000_000) {
        Ok(genesis) => genesis,
        Err(err) => panic!("GenesisBlock::new_with_timestamp failed: {err:?}"),
    };

    assert!(genesis.founder_wallet().is_none());
    assert_eq!(genesis.miner_for_genesis_block(), "");
    assert_eq!(genesis.prev_hash, [0u8; 64]);
}

#[test]
fn blockchain_74_001_builder_vector_genesis_new_with_miner_stores_founder_wallet() {
    let wallet = wallet_u64(74);

    let genesis = match GenesisBlock::new_with_timestamp_and_miner(
        "remzar genesis",
        1_700_000_000,
        &wallet,
    ) {
        Ok(genesis) => genesis,
        Err(err) => panic!("GenesisBlock::new_with_timestamp_and_miner failed: {err:?}"),
    };

    assert_eq!(genesis.founder_wallet(), Some(wallet.as_str()));
}

#[test]
fn blockchain_75_001_builder_vector_genesis_miner_for_genesis_block_returns_founder() {
    let wallet = wallet_u64(75);

    let genesis = match GenesisBlock::new_with_timestamp_and_miner(
        "remzar genesis",
        1_700_000_000,
        &wallet,
    ) {
        Ok(genesis) => genesis,
        Err(err) => panic!("GenesisBlock::new_with_timestamp_and_miner failed: {err:?}"),
    };

    assert_eq!(genesis.miner_for_genesis_block(), wallet);
}

#[test]
fn blockchain_76_001_builder_vector_genesis_hash_fields_are_64_byte_primitives() {
    let genesis = match GenesisBlock::new_with_timestamp("remzar genesis", 1_700_000_000) {
        Ok(genesis) => genesis,
        Err(err) => panic!("GenesisBlock::new_with_timestamp failed: {err:?}"),
    };

    assert_eq!(genesis.genesis_hash.len(), 64);
    assert_eq!(genesis.merkle_root.len(), 64);
    assert_eq!(genesis.prev_hash.len(), 64);
    assert_ne!(genesis.genesis_hash, [0u8; 64]);
}

#[test]
fn blockchain_77_001_builder_vector_metadata_from_genesis_roundtrip_policy() {
    let genesis = match GenesisBlock::new_with_timestamp("remzar genesis", 1_700_000_000) {
        Ok(genesis) => genesis,
        Err(err) => panic!("GenesisBlock::new_with_timestamp failed: {err:?}"),
    };

    let meta = match BlockMetadata::from_genesis(genesis) {
        Ok(meta) => meta,
        Err(err) => panic!("BlockMetadata::from_genesis failed: {err:?}"),
    };

    assert_eq!(meta.index, 0);
    assert_eq!(meta.previous_hash, [0u8; 64]);
    assert!(meta.puzzle_proof().is_none());
    assert!(meta.size >= GlobalConfiguration::MIN_BLOCK_SIZE);
}

#[test]
fn blockchain_78_001_builder_vector_genesis_block_connects_founder_to_block_miner() {
    let wallet = wallet_u64(78);

    let genesis = match GenesisBlock::new_with_timestamp_and_miner(
        "remzar genesis",
        1_700_000_000,
        &wallet,
    ) {
        Ok(genesis) => genesis,
        Err(err) => panic!("GenesisBlock::new_with_timestamp_and_miner failed: {err:?}"),
    };

    let meta = match BlockMetadata::from_genesis(genesis.clone()) {
        Ok(meta) => meta,
        Err(err) => panic!("BlockMetadata::from_genesis failed: {err:?}"),
    };

    let block = match Block::new(meta, None, genesis.miner_for_genesis_block(), 0) {
        Ok(block) => block,
        Err(err) => panic!("Block::new failed: {err:?}"),
    };

    assert_eq!(block.metadata.index, 0);
    assert_eq!(block.miner_wallet(), wallet.as_str());
}

#[test]
fn blockchain_79_001_builder_adversarial_buffered_gossip_proof_replays_after_parent_arrives() {
    let mut ctx = must_ctx("adversarial_buffered_gossip_proof_replays_after_parent_arrives");

    let parent = match extra_builder_make_parent_block(&ctx.wallet) {
        Ok(block) => block,
        Err(err) => panic!("failed to create parent block: {err}"),
    };

    let proof = match valid_unknown_parent_proof(&ctx.wallet, 1, parent.block_hash) {
        Ok(proof) => proof,
        Err(err) => panic!("failed to build valid proof: {err}"),
    };

    assert!(ctx.builder.on_puzzle_proof(&proof));
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent.block_hash),
        1
    );

    match extra_builder_store_existing_block(ctx.db.as_ref(), &parent, 0) {
        Ok(()) => {}
        Err(err) => panic!("failed to store parent block: {err}"),
    }

    let admitted = ctx
        .builder
        .consensus_mut()
        .replay_buffered_puzzle_proofs_for_parent(parent.block_hash);

    assert_eq!(admitted, 1);
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent.block_hash),
        0
    );
}

#[test]
fn blockchain_80_001_builder_load_remzarhash_batch_verification_for_metadata_set() {
    let items = (1u64..=32u64)
        .map(extra_builder_valid_metadata)
        .collect::<Vec<_>>();

    let hashes = match RemzarHash::compute_data_hash_batch(&items) {
        Ok(hashes) => hashes,
        Err(err) => panic!("compute_data_hash_batch failed: {err:?}"),
    };

    let verified = match RemzarHash::verify_data_hash_batch(&items, &hashes) {
        Ok(v) => v,
        Err(err) => panic!("verify_data_hash_batch failed: {err:?}"),
    };

    assert_eq!(hashes.len(), items.len());
    assert_eq!(verified.len(), items.len());
    assert!(verified.iter().all(|v| *v));
}

#[test]
fn blockchain_81_001_builder_edge_new_accepts_trimmed_wallet_and_canonicalizes() {
    let wallet = wallet_u64(81);
    let padded_wallet = format!("  {wallet}  ");
    let db = match new_db("edge_new_accepts_trimmed_wallet_and_canonicalizes", &wallet) {
        Ok(db) => db,
        Err(err) => panic!("db setup failed: {err}"),
    };

    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000)));
    let signing_key = match new_signing_key() {
        Ok(sk) => sk,
        Err(err) => panic!("signing key setup failed: {err}"),
    };

    let builder = match BlockchainBuilder::new(db, mempool, padded_wallet, tm, signing_key) {
        Ok(builder) => builder,
        Err(err) => panic!("BlockchainBuilder::new failed: {err:?}"),
    };

    assert_eq!(builder.consensus().local_wallet(), &wallet);
}

#[test]
fn blockchain_82_001_builder_edge_new_rejects_empty_wallet() {
    let wallet = wallet_u64(82);
    let db = match new_db("edge_new_rejects_empty_wallet", &wallet) {
        Ok(db) => db,
        Err(err) => panic!("db setup failed: {err}"),
    };

    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000)));
    let signing_key = match new_signing_key() {
        Ok(sk) => sk,
        Err(err) => panic!("signing key setup failed: {err}"),
    };

    let result = BlockchainBuilder::new(db, mempool, String::new(), tm, signing_key);

    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchain_83_001_builder_edge_runtime_catchup_gate_blocks_synced_mint() {
    let mut ctx =
        prepare_builder_with_parent_and_founder("edge_runtime_catchup_gate_blocks_synced_mint");

    ctx.builder
        .consensus_mut()
        .set_runtime_rejoin_catchup_gate(true, Some("catchup test".to_owned()));

    let result = ctx.builder.create_new_block(true);

    assert_result_err_contains(result, "catch");
}

#[test]
fn blockchain_84_001_builder_edge_branch_hydration_gate_blocks_synced_mint() {
    let mut ctx =
        prepare_builder_with_parent_and_founder("edge_branch_hydration_gate_blocks_synced_mint");

    ctx.builder
        .consensus_mut()
        .set_runtime_branch_hydration_active(true);

    let result = ctx.builder.create_new_block(true);

    assert_result_err_contains(result, "hydration");
}

#[test]
fn blockchain_85_001_builder_vector_reset_runtime_safety_state_allows_builder_state_to_continue() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_reset_runtime_safety_state_allows_builder_state_to_continue",
    );

    ctx.builder
        .consensus_mut()
        .set_runtime_rejoin_catchup_gate(true, Some("catchup".to_owned()));
    ctx.builder
        .consensus_mut()
        .set_runtime_branch_hydration_active(true);

    ctx.builder
        .consensus_mut()
        .reset_runtime_proposal_safety_state(0, nonzero_hash(85));

    assert!(!ctx.builder.consensus().runtime_rejoin_catchup_gate_active());
    assert!(!ctx.builder.consensus().runtime_branch_hydration_active());
    assert_eq!(
        ctx.builder.consensus().validator_state_rebuilt_at_tip(),
        Some(0)
    );
}

#[test]
fn blockchain_86_001_builder_vector_clear_runtime_tip_context_is_idempotent() {
    let mut ctx = must_ctx("vector_clear_runtime_tip_context_is_idempotent");

    ctx.builder
        .consensus_mut()
        .set_runtime_canonical_tip_context(7, nonzero_hash(86));
    ctx.builder
        .consensus_mut()
        .clear_runtime_canonical_tip_context();
    ctx.builder
        .consensus_mut()
        .clear_runtime_canonical_tip_context();

    assert_eq!(ctx.builder.consensus().local_wallet(), &ctx.wallet);
}

#[test]
fn blockchain_87_001_builder_vector_successful_mint_batch_key_matches_height_one() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_batch_key_matches_height_one",
    );

    let block = mint_one_block(&mut ctx);

    assert_eq!(block.batch_key.as_deref(), Some("tx_batch_0000000001"));
}

#[test]
fn blockchain_88_001_builder_vector_successful_mint_reward_matches_schedule_gate() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_reward_matches_schedule_gate",
    );

    let block = mint_one_block(&mut ctx);
    let delay = GlobalConfiguration::REWARD_DELAY_BLOCKS as u64;
    let expected = if block.metadata.index < delay {
        0
    } else {
        RewardHalving::get_block_reward(block.metadata.index)
    };

    assert_eq!(block.reward, expected);
}

#[test]
fn blockchain_89_001_builder_property_successful_mint_block_hash_verifies() {
    let mut ctx =
        prepare_builder_with_parent_and_founder("property_successful_mint_block_hash_verifies");

    let block = mint_one_block(&mut ctx);

    let verified = match block.verify_block_hash() {
        Ok(v) => v,
        Err(err) => panic!("verify_block_hash failed: {err:?}"),
    };

    assert!(verified);
}

#[test]
fn blockchain_90_001_builder_vector_successful_mint_serialized_block_roundtrip() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_serialized_block_roundtrip",
    );

    let block = mint_one_block(&mut ctx);
    let bytes = match block.serialize_for_storage() {
        Ok(bytes) => bytes,
        Err(err) => panic!("serialize_for_storage failed: {err:?}"),
    };

    let decoded = match Block::deserialize_from_storage(&bytes) {
        Ok(block) => block,
        Err(err) => panic!("deserialize_from_storage failed: {err:?}"),
    };

    assert_eq!(decoded.metadata.index, block.metadata.index);
    assert_eq!(decoded.block_hash, block.block_hash);
    assert_eq!(decoded.miner_wallet(), ctx.wallet.as_str());
}

#[test]
fn blockchain_91_001_builder_vector_successful_mint_latest_hash_matches_block_hash() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_latest_hash_matches_block_hash",
    );

    let block = mint_one_block(&mut ctx);

    let latest_hash = match ctx.db.get_latest_block_hash() {
        Ok(hash) => hash,
        Err(err) => panic!("get_latest_block_hash failed: {err:?}"),
    };

    assert_eq!(latest_hash, block.block_hash);
}

#[test]
fn blockchain_92_001_builder_vector_successful_mint_block_by_hash_is_same_block() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_block_by_hash_is_same_block",
    );

    let block = mint_one_block(&mut ctx);

    let by_hash = match ctx.db.get_block_by_hash(&block.block_hash) {
        Some(block) => block,
        None => panic!("expected block by hash after mint"),
    };

    assert_eq!(by_hash.metadata.index, block.metadata.index);
    assert_eq!(by_hash.block_hash, block.block_hash);
}

#[test]
fn blockchain_93_001_builder_vector_successful_mint_block_by_index_is_same_block() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_block_by_index_is_same_block",
    );

    let block = mint_one_block(&mut ctx);

    let by_index = match ctx.db.get_block_by_index(block.metadata.index) {
        Ok(Some(block)) => block,
        Ok(None) => panic!("expected block by index after mint"),
        Err(err) => panic!("get_block_by_index failed: {err:?}"),
    };

    assert_eq!(by_index.metadata.index, block.metadata.index);
    assert_eq!(by_index.block_hash, block.block_hash);
}

#[test]
fn blockchain_94_001_builder_vector_successful_mint_has_nonzero_guardian_signature() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_has_nonzero_guardian_signature",
    );

    let block = mint_one_block(&mut ctx);

    assert!(block.metadata.guardian_signature.iter().any(|b| *b != 0));
}

#[test]
fn blockchain_95_001_builder_vector_successful_mint_metadata_hash_verifies() {
    let mut ctx =
        prepare_builder_with_parent_and_founder("vector_successful_mint_metadata_hash_verifies");

    let block = mint_one_block(&mut ctx);
    let hash = match block.metadata.compute_hash() {
        Ok(hash) => hash,
        Err(err) => panic!("metadata compute_hash failed: {err:?}"),
    };

    let verified = match block.metadata.verify_hash(&hash) {
        Ok(v) => v,
        Err(err) => panic!("metadata verify_hash failed: {err:?}"),
    };

    assert!(verified);
}

#[test]
fn blockchain_96_001_builder_vector_successful_mint_puzzle_commitment_is_nonzero() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_puzzle_commitment_is_nonzero",
    );

    let block = mint_one_block(&mut ctx);
    let commitment = match block.metadata.puzzle_commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("puzzle_commitment_bytes failed: {err:?}"),
    };

    assert_ne!(commitment, [0u8; 64]);
}

#[test]
fn blockchain_97_001_builder_vector_successful_mint_puzzle_commitment_hex_is_128_chars() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "vector_successful_mint_puzzle_commitment_hex_is_128_chars",
    );

    let block = mint_one_block(&mut ctx);
    let hex = match block.metadata.puzzle_commitment_hex() {
        Ok(hex) => hex,
        Err(err) => panic!("puzzle_commitment_hex failed: {err:?}"),
    };

    assert_eq!(hex.len(), 128);
}

#[test]
fn blockchain_98_001_builder_property_two_sequential_mints_advance_tip_to_two() {
    let mut ctx =
        prepare_builder_with_parent_and_founder("property_two_sequential_mints_advance_tip_to_two");

    let first = mint_one_block(&mut ctx);
    assert_eq!(first.metadata.index, 1);

    let second = mint_one_block(&mut ctx);
    assert_eq!(second.metadata.index, 2);

    let tip = match ctx.db.get_tip_height() {
        Ok(tip) => tip,
        Err(err) => panic!("get_tip_height failed: {err:?}"),
    };

    assert_eq!(tip, 2);
}

#[test]
fn blockchain_99_001_builder_property_second_mint_links_to_first_hash() {
    let mut ctx =
        prepare_builder_with_parent_and_founder("property_second_mint_links_to_first_hash");

    let first = mint_one_block(&mut ctx);
    let second = mint_one_block(&mut ctx);

    assert_eq!(second.metadata.previous_hash, first.block_hash);
    assert_ne!(second.block_hash, first.block_hash);
}

#[test]
fn blockchain_100_001_builder_load_four_sequential_mints_keep_canonical_chain_links() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "load_four_sequential_mints_keep_canonical_chain_links",
    );

    let mut prev_hash = match ctx.db.get_latest_block_hash() {
        Ok(hash) => hash,
        Err(err) => panic!("get_latest_block_hash failed: {err:?}"),
    };

    for expected_height in 1u64..=4u64 {
        let block = mint_one_block(&mut ctx);

        assert_eq!(block.metadata.index, expected_height);
        assert_eq!(block.metadata.previous_hash, prev_hash);

        prev_hash = block.block_hash;
    }

    let tip = match ctx.db.get_tip_height() {
        Ok(tip) => tip,
        Err(err) => panic!("get_tip_height failed: {err:?}"),
    };

    assert_eq!(tip, 4);
}

#[test]
fn blockchain_101_001_builder_edge_metadata_rejects_puzzle_height_mismatch() {
    let mut meta = extra_builder_valid_metadata(10);
    let proof = extra_builder_block_proof(11, &wallet_u64(101), meta.previous_hash, 1);
    meta.set_puzzle_proof(Some(proof));

    let result = meta.validate_structural();

    assert_result_err_contains(result, "height");
}

#[test]
fn blockchain_102_001_builder_edge_metadata_rejects_puzzle_prev_hash_mismatch() {
    let mut meta = extra_builder_valid_metadata(10);
    let proof = extra_builder_block_proof(10, &wallet_u64(102), nonzero_hash(102), 1);
    meta.set_puzzle_proof(Some(proof));

    let result = meta.validate_structural();

    assert_result_err_contains(result, "prev");
}

#[test]
fn blockchain_103_001_builder_vector_metadata_set_and_clear_puzzle_proof() {
    let mut meta = extra_builder_valid_metadata(10);
    let proof = extra_builder_block_proof(10, &wallet_u64(103), meta.previous_hash, 1);

    meta.set_puzzle_proof(Some(proof));
    assert!(meta.puzzle_proof().is_some());

    meta.set_puzzle_proof(None);
    assert!(meta.puzzle_proof().is_none());
}

#[test]
fn blockchain_104_001_builder_property_block_puzzle_proof_commitment_is_stable() {
    let proof = extra_builder_block_proof(104, &wallet_u64(104), nonzero_hash(104), 123);

    let first = match proof.commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("first commitment failed: {err:?}"),
    };
    let second = match proof.commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("second commitment failed: {err:?}"),
    };

    assert_eq!(first, second);
    assert_ne!(first, [0u8; 64]);
}

#[test]
fn blockchain_105_001_builder_property_block_puzzle_proof_commitment_changes_with_output() {
    let wallet = wallet_u64(105);
    let prev = nonzero_hash(105);

    let first = extra_builder_block_proof(105, &wallet, prev, 1);
    let second = extra_builder_block_proof(105, &wallet, prev, 2);

    let first_commitment = match first.commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("first commitment failed: {err:?}"),
    };
    let second_commitment = match second.commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("second commitment failed: {err:?}"),
    };

    assert_ne!(first_commitment, second_commitment);
}

#[test]
fn blockchain_106_001_builder_adversarial_multiple_buffered_parents_are_isolated() {
    let mut ctx = must_ctx("adversarial_multiple_buffered_parents_are_isolated");
    let parent_a = nonzero_hash(106);
    let parent_b = nonzero_hash(107);

    let proof_a = match valid_unknown_parent_proof(&ctx.wallet, 106, parent_a) {
        Ok(proof) => proof,
        Err(err) => panic!("proof_a failed: {err}"),
    };
    let proof_b = match valid_unknown_parent_proof(&ctx.wallet, 107, parent_b) {
        Ok(proof) => proof,
        Err(err) => panic!("proof_b failed: {err}"),
    };

    assert!(ctx.builder.on_puzzle_proof(&proof_a));
    assert!(ctx.builder.on_puzzle_proof(&proof_b));

    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent_a),
        1
    );
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent_b),
        1
    );
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_total(),
        2
    );
}

#[test]
fn blockchain_107_001_builder_adversarial_replay_unknown_parent_skips_without_removing() {
    let mut ctx = must_ctx("adversarial_replay_unknown_parent_skips_without_removing");
    let parent = nonzero_hash(108);

    let proof = match valid_unknown_parent_proof(&ctx.wallet, 108, parent) {
        Ok(proof) => proof,
        Err(err) => panic!("proof failed: {err}"),
    };

    assert!(ctx.builder.on_puzzle_proof(&proof));

    let admitted = ctx
        .builder
        .consensus_mut()
        .replay_buffered_puzzle_proofs_for_parent(parent);

    assert_eq!(admitted, 0);
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        1
    );
}

#[test]
fn blockchain_108_001_builder_adversarial_replay_two_buffered_proofs_for_known_parent() {
    let mut ctx = must_ctx("adversarial_replay_two_buffered_proofs_for_known_parent");

    let parent = match extra_builder_make_parent_block(&ctx.wallet) {
        Ok(block) => block,
        Err(err) => panic!("failed to make parent block: {err}"),
    };

    let first = match valid_unknown_parent_proof(&ctx.wallet, 1, parent.block_hash) {
        Ok(proof) => proof,
        Err(err) => panic!("first proof failed: {err}"),
    };
    let second = match valid_unknown_parent_proof(&ctx.wallet, 2, parent.block_hash) {
        Ok(proof) => proof,
        Err(err) => panic!("second proof failed: {err}"),
    };

    assert!(ctx.builder.on_puzzle_proof(&first));
    assert!(ctx.builder.on_puzzle_proof(&second));
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent.block_hash),
        2
    );

    match extra_builder_store_existing_block(ctx.db.as_ref(), &parent, 0) {
        Ok(()) => {}
        Err(err) => panic!("failed to store parent block: {err}"),
    }

    let admitted = ctx
        .builder
        .consensus_mut()
        .replay_buffered_puzzle_proofs_for_parent(parent.block_hash);

    assert_eq!(admitted, 2);
    assert_eq!(
        ctx.builder
            .consensus()
            .pending_buffered_puzzle_proof_count_for_parent(parent.block_hash),
        0
    );
}

#[test]
fn blockchain_109_001_builder_fuzz_remzar_amount_parser_vectors_are_deterministic() {
    let cases = [
        ("1", UNIT_DIVISOR),
        ("1.00000000", UNIT_DIVISOR),
        ("0.00000001", 1),
        ("0.000000001", 0),
        ("-1", 0),
        ("+1", 0),
        ("1e2", 0),
        ("1.2.3", 0),
        ("", 0),
    ];

    for (input, expected) in cases {
        assert_eq!(to_micro_units_str(input), expected, "input={input}");
    }
}

#[test]
fn blockchain_110_001_builder_vector_remzar_formatting_matches_micro_units() {
    assert_eq!(format_remzar(0), "0.00000000");
    assert_eq!(format_remzar(1), "0.00000001");
    assert_eq!(format_remzar(UNIT_DIVISOR), "1.00000000");
    assert_eq!(format_remzar_trim(UNIT_DIVISOR), "1");
}

#[test]
fn blockchain_111_001_builder_vector_global_genesis_hash_hex_decodes_to_64_bytes() {
    let decoded = match decode_hex_to_64(GlobalConfiguration::GENESIS_HASH_HEX) {
        Ok(bytes) => bytes,
        Err(err) => panic!("decode_hex_to_64 failed: {err:?}"),
    };

    assert_eq!(decoded.len(), 64);
    assert_ne!(decoded, [0u8; 64]);
}

#[test]
fn blockchain_112_001_builder_edge_decode_hex_to_64_rejects_short_hex() {
    let result = decode_hex_to_64("abcd");

    assert_result_err_contains(result, "hex");
}

#[test]
fn blockchain_113_001_builder_edge_genesis_with_invalid_miner_is_rejected() {
    let result =
        GenesisBlock::new_with_timestamp_and_miner("remzar genesis", 1_700_000_000, "not-a-wallet");

    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchain_114_001_builder_property_genesis_hash_is_stable_for_same_inputs() {
    let wallet = wallet_u64(114);

    let first = match GenesisBlock::new_with_timestamp_and_miner(
        "remzar genesis",
        1_700_000_000,
        &wallet,
    ) {
        Ok(genesis) => genesis,
        Err(err) => panic!("first genesis failed: {err:?}"),
    };

    let second = match GenesisBlock::new_with_timestamp_and_miner(
        "remzar genesis",
        1_700_000_000,
        &wallet,
    ) {
        Ok(genesis) => genesis,
        Err(err) => panic!("second genesis failed: {err:?}"),
    };

    assert_eq!(first.genesis_hash, second.genesis_hash);
    assert_eq!(first.merkle_root, second.merkle_root);
    assert_eq!(first.prev_hash, second.prev_hash);
}

#[test]
fn blockchain_115_001_builder_property_genesis_hash_does_not_depend_on_founder_wallet() {
    let first = match GenesisBlock::new_with_timestamp_and_miner(
        "remzar genesis",
        1_700_000_000,
        &wallet_u64(115),
    ) {
        Ok(genesis) => genesis,
        Err(err) => panic!("first genesis failed: {err:?}"),
    };

    let second = match GenesisBlock::new_with_timestamp_and_miner(
        "remzar genesis",
        1_700_000_000,
        &wallet_u64(116),
    ) {
        Ok(genesis) => genesis,
        Err(err) => panic!("second genesis failed: {err:?}"),
    };

    assert_eq!(first.genesis_hash, second.genesis_hash);
    assert_ne!(first.founder_wallet(), second.founder_wallet());
}

#[test]
fn blockchain_116_001_builder_vector_genesis_founder_metadata_block_is_valid_builder_parent() {
    let wallet = wallet_u64(116);

    let genesis = match GenesisBlock::new_with_timestamp_and_miner(
        "remzar genesis",
        1_700_000_000,
        &wallet,
    ) {
        Ok(genesis) => genesis,
        Err(err) => panic!("GenesisBlock failed: {err:?}"),
    };

    let meta = match BlockMetadata::from_genesis(genesis.clone()) {
        Ok(meta) => meta,
        Err(err) => panic!("BlockMetadata::from_genesis failed: {err:?}"),
    };

    let block = match Block::new(meta, None, genesis.miner_for_genesis_block(), 0) {
        Ok(block) => block,
        Err(err) => panic!("Block::new failed: {err:?}"),
    };

    assert_eq!(block.metadata.index, 0);
    assert_eq!(block.miner_wallet(), wallet.as_str());
    assert_ne!(block.block_hash, [0u8; 64]);
}

#[test]
fn blockchain_117_001_builder_load_many_builder_contexts_initialize_cleanly() {
    for index in 0u64..12u64 {
        let name = format!("load_many_builder_contexts_initialize_cleanly_{index}");
        let ctx = must_ctx(&name);

        assert_eq!(ctx.builder.consensus().local_wallet(), &ctx.wallet);
        assert!(ctx.builder.pending_puzzle_proof().is_none());
    }
}

#[test]
fn blockchain_118_001_builder_load_hash_many_minted_blocks() {
    let mut ctx = prepare_builder_with_parent_and_founder("load_hash_many_minted_blocks");

    let blocks = (0u64..4u64)
        .map(|_| mint_one_block(&mut ctx))
        .collect::<Vec<_>>();

    let hashes = match RemzarHash::compute_data_hash_batch(&blocks) {
        Ok(hashes) => hashes,
        Err(err) => panic!("compute_data_hash_batch failed: {err:?}"),
    };

    assert_eq!(hashes.len(), blocks.len());
    assert!(hashes.iter().all(|h| h.len() == 128));
}

#[test]
fn blockchain_119_001_builder_property_minted_block_hashes_are_unique_across_chain() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "property_minted_block_hashes_are_unique_across_chain",
    );

    let mut hashes = std::collections::BTreeSet::new();

    for _ in 0u64..4u64 {
        let block = mint_one_block(&mut ctx);
        assert!(hashes.insert(block.block_hash));
    }

    assert_eq!(hashes.len(), 4);
}

#[test]
fn blockchain_120_001_builder_load_final_chain_tip_and_hash_are_consistent_after_five_mints() {
    let mut ctx = prepare_builder_with_parent_and_founder(
        "load_final_chain_tip_and_hash_are_consistent_after_five_mints",
    );

    let mut last_block = None;

    for expected_height in 1u64..=5u64 {
        let block = mint_one_block(&mut ctx);
        assert_eq!(block.metadata.index, expected_height);
        last_block = Some(block);
    }

    let final_block = match last_block {
        Some(block) => block,
        None => panic!("expected final block"),
    };

    let tip = match ctx.db.get_tip_height() {
        Ok(tip) => tip,
        Err(err) => panic!("get_tip_height failed: {err:?}"),
    };
    let latest_hash = match ctx.db.get_latest_block_hash() {
        Ok(hash) => hash,
        Err(err) => panic!("get_latest_block_hash failed: {err:?}"),
    };

    assert_eq!(tip, 5);
    assert_eq!(latest_hash, final_block.block_hash);
}
