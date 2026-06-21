// tests/blockchain_000_consensus_tests.rs

use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_003_puzzleproof::BlockPuzzleProof;
use remzar::blockchain::blockchain_000_consensus::BlockchainConsensus;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::consensus::por_000_ephemeral_registration::RegistryData;
use remzar::consensus::por_001_consensus_config::{PorConsensusConfig, PorPuzzleKind};
use remzar::consensus::por_002_puzzle_engine::PorPuzzleEngine;
use remzar::consensus::por_003_puzzle_pool::PorPuzzlePool;
use remzar::consensus::por_004_puzzle_proof::PorPuzzleProof;
use remzar::consensus::por_005_time_management::{TimeConfig, TimeManager};
use remzar::consensus::por_006_committee_eligibility::{
    CommitteeEligibility, CommitteeEligibilityConfig, CommitteeStatusUpdate, IneligibilityReason,
};
use remzar::consensus::por_007_leader_schedule::{CommitteeSnapshot, LeaderSchedule};
use remzar::consensus::por_008_validator_lifecycle::{
    RegisterOutcome, ValidatorLifecycle, ValidatorLifecycleConfig, ValidatorMeta,
};
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestCtx {
    consensus: BlockchainConsensus,
    local_wallet: String,
}

fn err_to_string<E: core::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn wallet_from_seed(seed: u8) -> String {
    let n = u16::from(seed).saturating_add(1);
    format!("r{n:0128x}")
}

fn wallet_with_hex_char(c: char) -> String {
    let body = c.to_string().repeat(128);
    format!("r{body}")
}

fn nonzero_hash(seed: u8) -> [u8; 64] {
    let fill = if seed == 0 { 1 } else { seed };
    [fill; 64]
}

fn unique_test_dir(name: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "remzar_blockchain_01_000_consensus_tests_{name}_{}_{}",
        std::process::id(),
        id
    ));

    match fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(_err) => {}
    }

    dir
}

fn path_to_string(path: &Path) -> Result<String, String> {
    match path.to_str() {
        Some(s) => Ok(s.to_owned()),
        None => Err(format!("path is not valid UTF-8: {}", path.display())),
    }
}

fn new_db_and_tm(name: &str) -> Result<(Arc<RockDBManager>, Arc<TimeManager>, String), String> {
    let base_dir = unique_test_dir(name);
    let blockchain_dir = base_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);

    let local_wallet = wallet_from_seed(1);

    let opts = NodeOpts {
        data_dir: path_to_string(&base_dir)?,
        identity_file: path_to_string(&base_dir.join("identity.key"))?,
        wallet_address: local_wallet.clone(),
        ..NodeOpts::default()
    };

    let blockchain_dir_str = path_to_string(&blockchain_dir)?;
    let db_inner =
        RockDBManager::new_blockchain(&opts, &blockchain_dir_str).map_err(err_to_string)?;

    db_inner.set_latest_block_index(0).map_err(err_to_string)?;

    let db = Arc::new(db_inner);
    let tm = Arc::new(TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000)));

    Ok((db, tm, local_wallet))
}

fn new_ctx(name: &str) -> Result<TestCtx, String> {
    let (db, tm, local_wallet) = new_db_and_tm(name)?;
    let consensus =
        BlockchainConsensus::new(Arc::clone(&db), local_wallet.clone(), Arc::clone(&tm))
            .map_err(err_to_string)?;

    Ok(TestCtx {
        consensus,
        local_wallet,
    })
}

fn must_ctx(name: &str) -> TestCtx {
    match new_ctx(name) {
        Ok(ctx) => ctx,
        Err(err) => panic!("failed to build test context for {name}: {err}"),
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

fn valid_gossip_proof_for_extra_tests(
    wallet: &str,
    height: u64,
    prev_block_hash: [u8; 64],
) -> PorPuzzleProof {
    match valid_unknown_parent_proof(wallet, height, prev_block_hash) {
        Ok(proof) => proof,
        Err(err) => panic!("failed to build valid gossip proof: {err}"),
    }
}

fn must_block_puzzle_proof(
    wallet: &str,
    height: u64,
    prev_block_hash: [u8; 64],
) -> BlockPuzzleProof {
    let gossip = valid_gossip_proof_for_extra_tests(wallet, height, prev_block_hash);

    match BlockPuzzleProof::from_gossip(&gossip) {
        Ok(proof) => proof,
        Err(err) => panic!("BlockPuzzleProof::from_gossip failed: {err:?}"),
    }
}

fn nonzero_sig(seed: u8) -> [u8; ml_dsa_65::SIG_LEN] {
    let fill = if seed == 0 { 1 } else { seed };
    [fill; ml_dsa_65::SIG_LEN]
}

fn wallet_u64(seed: u64) -> String {
    format!("r{:0128x}", seed.saturating_add(1))
}

fn wallet_str_from_register_tx(tx: &RegisterNodeTx) -> String {
    match tx.wallet_str() {
        Ok(s) => s.to_owned(),
        Err(err) => panic!("RegisterNodeTx wallet_str failed: {err:?}"),
    }
}

fn valid_metadata_for_extra_tests(proof: Option<BlockPuzzleProof>) -> BlockMetadata {
    BlockMetadata::new(
        5,
        1_700_000_000,
        nonzero_hash(21),
        nonzero_hash(22),
        nonzero_sig(23),
        proof,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    )
}

#[test]
fn blockchainconsensus_01_vector_new_canonicalizes_local_wallet() {
    let ctx = must_ctx("vector_new_canonicalizes_local_wallet");

    assert_eq!(
        ctx.consensus.local_wallet().as_str(),
        ctx.local_wallet.as_str()
    );
    assert!(ctx.local_wallet.starts_with('r'));
    assert_eq!(ctx.local_wallet.len(), 129);
}

#[test]
fn blockchainconsensus_02_edge_new_rejects_invalid_local_wallet() {
    let (db, tm, _wallet) = match new_db_and_tm("edge_new_rejects_invalid_local_wallet") {
        Ok(v) => v,
        Err(err) => panic!("failed to create db/tm: {err}"),
    };

    let result = BlockchainConsensus::new(db, "not-a-wallet".to_owned(), tm);
    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchainconsensus_03_vector_validator_state_starts_without_unknown_wallet() {
    let ctx = must_ctx("vector_validator_state_starts_without_unknown_wallet");
    let other = wallet_from_seed(9);

    let known = match ctx.consensus.validator_state().is_canonically_known(&other) {
        Ok(v) => v,
        Err(err) => panic!("canonical known check failed: {err:?}"),
    };

    assert!(!known);
}

#[test]
fn blockchainconsensus_04_vector_seed_genesis_founder_becomes_canonically_known() {
    let mut ctx = must_ctx("vector_seed_genesis_founder_becomes_canonically_known");

    match ctx
        .consensus
        .validator_state_mut()
        .seed_genesis_founder(&ctx.local_wallet, 1_700_000_000)
    {
        Ok(()) => {}
        Err(err) => panic!("seed_genesis_founder failed: {err:?}"),
    }

    let known = match ctx
        .consensus
        .validator_state()
        .is_canonically_known(&ctx.local_wallet)
    {
        Ok(v) => v,
        Err(err) => panic!("canonical known check failed: {err:?}"),
    };

    assert!(known);
}

#[test]
fn blockchainconsensus_05_vector_initial_validator_state_rebuilt_tip_is_zero() {
    let ctx = must_ctx("vector_initial_validator_state_rebuilt_tip_is_zero");

    assert_eq!(ctx.consensus.validator_state_rebuilt_at_tip(), Some(0));
}

#[test]
fn blockchainconsensus_06_vector_note_validator_state_rebuilt_to_tip_updates_marker() {
    let mut ctx = must_ctx("vector_note_validator_state_rebuilt_to_tip_updates_marker");

    ctx.consensus.note_validator_state_rebuilt_to_tip(11);

    assert_eq!(ctx.consensus.validator_state_rebuilt_at_tip(), Some(11));
}

#[test]
fn blockchainconsensus_07_vector_reset_runtime_proposal_safety_state_clears_gates() {
    let mut ctx = must_ctx("vector_reset_runtime_proposal_safety_state_clears_gates");

    ctx.consensus
        .set_runtime_rejoin_catchup_gate(true, Some("test catchup".to_owned()));
    ctx.consensus.set_runtime_branch_hydration_active(true);

    ctx.consensus
        .reset_runtime_proposal_safety_state(7, nonzero_hash(7));

    assert!(!ctx.consensus.runtime_rejoin_catchup_gate_active());
    assert!(!ctx.consensus.runtime_branch_hydration_active());
    assert_eq!(ctx.consensus.validator_state_rebuilt_at_tip(), Some(7));
}

#[test]
fn blockchainconsensus_08_edge_rejoin_catchup_gate_toggles_on_and_off() {
    let mut ctx = must_ctx("edge_rejoin_catchup_gate_toggles_on_and_off");

    ctx.consensus
        .set_runtime_rejoin_catchup_gate(true, Some("network rejoin".to_owned()));
    assert!(ctx.consensus.runtime_rejoin_catchup_gate_active());

    ctx.consensus.set_runtime_rejoin_catchup_gate(false, None);
    assert!(!ctx.consensus.runtime_rejoin_catchup_gate_active());
}

#[test]
fn blockchainconsensus_09_edge_branch_hydration_gate_toggles_on_and_off() {
    let mut ctx = must_ctx("edge_branch_hydration_gate_toggles_on_and_off");

    ctx.consensus.set_runtime_branch_hydration_active(true);
    assert!(ctx.consensus.runtime_branch_hydration_active());

    ctx.consensus.set_runtime_branch_hydration_active(false);
    assert!(!ctx.consensus.runtime_branch_hydration_active());
}

#[test]
fn blockchainconsensus_10_vector_clear_pending_puzzle_proof_is_empty_on_fresh_engine() {
    let mut ctx = must_ctx("vector_clear_pending_puzzle_proof_is_empty_on_fresh_engine");

    assert!(ctx.consensus.pending_puzzle_proof().is_none());
    assert!(ctx.consensus.clear_pending_puzzle_proof().is_none());
    assert!(ctx.consensus.take_pending_puzzle_proof().is_none());
}

#[test]
fn blockchainconsensus_11_vector_set_registry_marks_single_wallet_live() {
    let mut ctx = must_ctx("vector_set_registry_marks_single_wallet_live");
    let reg = must_registry(&[ctx.local_wallet.clone()]);

    ctx.consensus.set_registry(reg);

    assert!(
        ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&ctx.local_wallet)
    );
}

#[test]
fn blockchainconsensus_12_vector_set_registry_marks_multiple_wallets_live() {
    let mut ctx = must_ctx("vector_set_registry_marks_multiple_wallets_live");
    let w2 = wallet_from_seed(2);
    let w3 = wallet_from_seed(3);
    let reg = must_registry(&[ctx.local_wallet.clone(), w2.clone(), w3.clone()]);

    ctx.consensus.set_registry(reg);

    assert!(
        ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&ctx.local_wallet)
    );
    assert!(ctx.consensus.committee_eligibility().is_wallet_live(&w2));
    assert!(ctx.consensus.committee_eligibility().is_wallet_live(&w3));
}

#[test]
fn blockchainconsensus_13_vector_collect_register_node_txs_empty_registry_returns_empty() {
    let ctx = must_ctx("vector_collect_register_node_txs_empty_registry_returns_empty");

    let txs = ctx.consensus.collect_register_node_txs_for_block(1);

    assert!(txs.is_empty());
}

#[test]
fn blockchainconsensus_14_vector_collect_register_node_txs_one_runtime_wallet_returns_one() {
    let mut ctx = must_ctx("vector_collect_register_node_txs_one_runtime_wallet_returns_one");
    let reg = must_registry(&[ctx.local_wallet.clone()]);

    ctx.consensus.set_registry(reg);
    let txs = ctx.consensus.collect_register_node_txs_for_block(1);

    assert_eq!(txs.len(), 1);
}

#[test]
fn blockchainconsensus_15_edge_collect_register_node_txs_skips_canonical_founder() {
    let mut ctx = must_ctx("edge_collect_register_node_txs_skips_canonical_founder");
    let reg = must_registry(&[ctx.local_wallet.clone()]);

    match ctx
        .consensus
        .validator_state_mut()
        .seed_genesis_founder(&ctx.local_wallet, 1_700_000_000)
    {
        Ok(()) => {}
        Err(err) => panic!("seed_genesis_founder failed: {err:?}"),
    }

    ctx.consensus.set_registry(reg);
    let txs = ctx.consensus.collect_register_node_txs_for_block(1);

    assert!(txs.is_empty());
}

#[test]
fn blockchainconsensus_16_load_collect_register_node_txs_eight_runtime_wallets() {
    let mut ctx = must_ctx("load_collect_register_node_txs_eight_runtime_wallets");

    let wallets: Vec<String> = (0u8..8u8).map(wallet_from_seed).collect();
    let reg = must_registry(&wallets);

    ctx.consensus.set_registry(reg);
    let txs = ctx.consensus.collect_register_node_txs_for_block(1);

    assert_eq!(txs.len(), wallets.len());
}

#[test]
fn blockchainconsensus_17_load_collect_register_node_txs_thirty_two_runtime_wallets() {
    let mut ctx = must_ctx("load_collect_register_node_txs_thirty_two_runtime_wallets");

    let wallets: Vec<String> = (0u8..32u8).map(wallet_from_seed).collect();
    let reg = must_registry(&wallets);

    ctx.consensus.set_registry(reg);
    let txs = ctx.consensus.collect_register_node_txs_for_block(1);

    assert_eq!(txs.len(), wallets.len());
}

#[test]
fn blockchainconsensus_18_property_collect_register_node_txs_is_stable_for_same_registry() {
    let mut ctx = must_ctx("property_collect_register_node_txs_is_stable_for_same_registry");

    let wallets: Vec<String> = (2u8..10u8).map(wallet_from_seed).collect();
    let reg = must_registry(&wallets);

    ctx.consensus.set_registry(reg);

    let first = ctx.consensus.collect_register_node_txs_for_block(1);
    let second = ctx.consensus.collect_register_node_txs_for_block(1);

    assert_eq!(first.len(), second.len());
    assert_eq!(first.len(), wallets.len());
}

#[test]
fn blockchainconsensus_19_vector_set_committee_eligibility_replaces_policy_object() {
    let mut ctx = must_ctx("vector_set_committee_eligibility_replaces_policy_object");

    let cfg = CommitteeEligibilityConfig {
        require_synced: true,
        ..CommitteeEligibilityConfig::default()
    };

    let ce = CommitteeEligibility::new(cfg);
    ctx.consensus.set_committee_eligibility(ce);

    assert!(
        ctx.consensus
            .committee_eligibility()
            .config()
            .require_synced
    );
}

#[test]
fn blockchainconsensus_20_edge_committee_mut_update_not_live_makes_wallet_ineligible() {
    let mut ctx = must_ctx("edge_committee_mut_update_not_live_makes_wallet_ineligible");

    let update = CommitteeStatusUpdate {
        is_live: false,
        has_synced: true,
        local_tip: 10,
        network_tip: 10,
        peers_connected: 1,
        connected_wallet_peers: 1,
    };

    match ctx
        .consensus
        .committee_eligibility_mut()
        .update_local_status(&ctx.local_wallet, update)
    {
        Ok(()) => {}
        Err(err) => panic!("update_local_status failed: {err:?}"),
    }

    let decision = ctx
        .consensus
        .committee_eligibility()
        .decide_wallet(&ctx.local_wallet);

    assert!(!decision.eligible);
    assert!(decision.reasons.contains(&IneligibilityReason::NotLive));
}

#[test]
fn blockchainconsensus_21_vector_live_wallet_without_status_is_runtime_ready() {
    let mut ctx = must_ctx("vector_live_wallet_without_status_is_runtime_ready");
    let reg = must_registry(&[ctx.local_wallet.clone()]);

    ctx.consensus.set_registry(reg);

    let decision = ctx
        .consensus
        .committee_eligibility()
        .decide_wallet(&ctx.local_wallet);

    assert!(decision.eligible);
    assert!(decision.reasons.is_empty());
}

#[test]
fn blockchainconsensus_22_edge_require_synced_blocks_unsynced_wallet() {
    let mut ctx = must_ctx("edge_require_synced_blocks_unsynced_wallet");

    ctx.consensus
        .committee_eligibility_mut()
        .config_mut()
        .require_synced = true;

    let update = CommitteeStatusUpdate {
        is_live: true,
        has_synced: false,
        local_tip: 8,
        network_tip: 8,
        peers_connected: 1,
        connected_wallet_peers: 1,
    };

    match ctx
        .consensus
        .committee_eligibility_mut()
        .update_local_status(&ctx.local_wallet, update)
    {
        Ok(()) => {}
        Err(err) => panic!("update_local_status failed: {err:?}"),
    }

    let decision = ctx
        .consensus
        .committee_eligibility()
        .decide_wallet(&ctx.local_wallet);

    assert!(!decision.eligible);
    assert!(decision.reasons.contains(&IneligibilityReason::NotSynced));
}

#[test]
fn blockchainconsensus_23_edge_tip_lag_blocks_wallet_that_is_too_far_behind() {
    let mut ctx = must_ctx("edge_tip_lag_blocks_wallet_that_is_too_far_behind");

    ctx.consensus
        .committee_eligibility_mut()
        .config_mut()
        .max_tip_lag_blocks = 2;

    let update = CommitteeStatusUpdate {
        is_live: true,
        has_synced: true,
        local_tip: 1,
        network_tip: 9,
        peers_connected: 1,
        connected_wallet_peers: 1,
    };

    match ctx
        .consensus
        .committee_eligibility_mut()
        .update_local_status(&ctx.local_wallet, update)
    {
        Ok(()) => {}
        Err(err) => panic!("update_local_status failed: {err:?}"),
    }

    let decision = ctx
        .consensus
        .committee_eligibility()
        .decide_wallet(&ctx.local_wallet);

    assert!(!decision.eligible);
    assert!(decision.reasons.iter().any(|r| {
        matches!(
            r,
            IneligibilityReason::TooFarBehind {
                lag: 8,
                max_allowed: 2
            }
        )
    }));
}

#[test]
fn blockchainconsensus_24_adversarial_multi_node_isolation_blocks_local_mint_readiness() {
    let mut ctx = must_ctx("adversarial_multi_node_isolation_blocks_local_mint_readiness");
    let peer_wallet = wallet_from_seed(8);

    ctx.consensus
        .set_registry(must_registry(&[ctx.local_wallet.clone(), peer_wallet]));

    {
        let cfg = ctx.consensus.committee_eligibility_mut().config_mut();
        cfg.require_non_isolated = true;
        cfg.min_peers_connected = 1;
        cfg.min_connected_wallet_peers = 1;
    }

    let update = CommitteeStatusUpdate {
        is_live: true,
        has_synced: true,
        local_tip: 10,
        network_tip: 10,
        peers_connected: 0,
        connected_wallet_peers: 0,
    };

    match ctx
        .consensus
        .committee_eligibility_mut()
        .update_local_status(&ctx.local_wallet, update)
    {
        Ok(()) => {}
        Err(err) => panic!("update_local_status failed: {err:?}"),
    }

    let decision = ctx
        .consensus
        .committee_eligibility()
        .decide_wallet(&ctx.local_wallet);

    assert!(!decision.eligible);
    assert!(decision.reasons.contains(&IneligibilityReason::Isolated));
}

#[test]
fn blockchainconsensus_25_property_solo_wallet_does_not_fail_only_for_isolation() {
    let mut ctx = must_ctx("property_solo_wallet_does_not_fail_only_for_isolation");

    ctx.consensus
        .set_registry(must_registry(&[ctx.local_wallet.clone()]));

    {
        let cfg = ctx.consensus.committee_eligibility_mut().config_mut();
        cfg.require_non_isolated = true;
        cfg.min_peers_connected = 3;
        cfg.min_connected_wallet_peers = 3;
    }

    let update = CommitteeStatusUpdate {
        is_live: true,
        has_synced: true,
        local_tip: 10,
        network_tip: 10,
        peers_connected: 0,
        connected_wallet_peers: 0,
    };

    match ctx
        .consensus
        .committee_eligibility_mut()
        .update_local_status(&ctx.local_wallet, update)
    {
        Ok(()) => {}
        Err(err) => panic!("update_local_status failed: {err:?}"),
    }

    let decision = ctx
        .consensus
        .committee_eligibility()
        .decide_wallet(&ctx.local_wallet);

    assert!(decision.eligible);
}

#[test]
fn blockchainconsensus_26_vector_filter_candidates_keeps_only_runtime_ready_wallets() {
    let mut ctx = must_ctx("vector_filter_candidates_keeps_only_runtime_ready_wallets");
    let w2 = wallet_from_seed(2);

    ctx.consensus
        .set_registry(must_registry(&[ctx.local_wallet.clone()]));

    let candidates = vec![ctx.local_wallet.clone(), w2];
    let kept = ctx
        .consensus
        .committee_eligibility()
        .filter_candidates(candidates);

    assert_eq!(kept.len(), 1);
    assert_eq!(
        kept.first().map(String::as_str),
        Some(ctx.local_wallet.as_str())
    );
}

#[test]
fn blockchainconsensus_27_vector_all_runtime_decisions_reports_live_wallet() {
    let mut ctx = must_ctx("vector_all_runtime_decisions_reports_live_wallet");

    ctx.consensus
        .set_registry(must_registry(&[ctx.local_wallet.clone()]));

    let decisions = ctx
        .consensus
        .committee_eligibility()
        .all_runtime_decisions();

    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions.first().map(|d| d.wallet.as_str()),
        Some(ctx.local_wallet.as_str())
    );
}

#[test]
fn blockchainconsensus_28_adversarial_puzzle_proof_height_zero_is_rejected() {
    let mut ctx = must_ctx("adversarial_puzzle_proof_height_zero_is_rejected");

    let proof = invalid_proof(0, ctx.local_wallet.clone(), nonzero_hash(3), 1);

    assert!(!ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_29_adversarial_puzzle_proof_noncanonical_wallet_is_rejected() {
    let mut ctx = must_ctx("adversarial_puzzle_proof_noncanonical_wallet_is_rejected");

    let proof = invalid_proof(1, "bad-wallet".to_owned(), nonzero_hash(3), 1);

    assert!(!ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_30_adversarial_puzzle_proof_zero_parent_hash_is_rejected() {
    let mut ctx = must_ctx("adversarial_puzzle_proof_zero_parent_hash_is_rejected");

    let proof = invalid_proof(1, ctx.local_wallet.clone(), [0u8; 64], 1);

    assert!(!ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_31_adversarial_puzzle_proof_ff_parent_hash_is_rejected() {
    let mut ctx = must_ctx("adversarial_puzzle_proof_ff_parent_hash_is_rejected");

    let proof = invalid_proof(1, ctx.local_wallet.clone(), [0xFFu8; 64], 1);

    assert!(!ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_32_adversarial_puzzle_proof_zero_output_is_rejected() {
    let mut ctx = must_ctx("adversarial_puzzle_proof_zero_output_is_rejected");

    let proof = invalid_proof(1, ctx.local_wallet.clone(), nonzero_hash(5), 0);

    assert!(!ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_33_fuzz_puzzle_proof_height_upper_bound_is_rejected() {
    let mut ctx = must_ctx("fuzz_puzzle_proof_height_upper_bound_is_rejected");

    let proof = invalid_proof(10_000_001, ctx.local_wallet.clone(), nonzero_hash(5), 1);

    assert!(!ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_34_adversarial_valid_unknown_parent_proof_buffers_and_deduplicates() {
    let mut ctx = must_ctx("adversarial_valid_unknown_parent_proof_buffers_and_deduplicates");
    let prev = nonzero_hash(42);

    let proof = match valid_unknown_parent_proof(&ctx.local_wallet, 2, prev) {
        Ok(p) => p,
        Err(err) => panic!("failed to build valid proof: {err}"),
    };

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(prev),
        1
    );

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(prev),
        1
    );
}

#[test]
fn blockchainconsensus_35_adversarial_replay_unknown_parent_does_not_admit_buffered_proof() {
    let mut ctx = must_ctx("adversarial_replay_unknown_parent_does_not_admit_buffered_proof");
    let prev = nonzero_hash(43);

    let proof = match valid_unknown_parent_proof(&ctx.local_wallet, 3, prev) {
        Ok(p) => p,
        Err(err) => panic!("failed to build valid proof: {err}"),
    };

    assert!(ctx.consensus.on_puzzle_proof(&proof));

    let admitted = ctx.consensus.replay_buffered_puzzle_proofs_for_parent(prev);

    assert_eq!(admitted, 0);
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
}

#[test]
fn blockchainconsensus_36_load_gc_puzzle_pool_below_removes_old_buffered_proofs() {
    let mut ctx = must_ctx("load_gc_puzzle_pool_below_removes_old_buffered_proofs");
    let prev = nonzero_hash(44);

    let proof = match valid_unknown_parent_proof(&ctx.local_wallet, 4, prev) {
        Ok(p) => p,
        Err(err) => panic!("failed to build valid proof: {err}"),
    };

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);

    ctx.consensus.gc_puzzle_pool_below(5);

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_37_edge_assert_can_build_block_rejects_bypass_leader() {
    let mut ctx = must_ctx("edge_assert_can_build_block_rejects_bypass_leader");

    let result = ctx
        .consensus
        .assert_can_build_block(1, nonzero_hash(9), true);

    assert_result_err_contains(result, "bypass_leader");
}

#[test]
fn blockchainconsensus_38_edge_assert_can_build_block_rejects_height_zero() {
    let mut ctx = must_ctx("edge_assert_can_build_block_rejects_height_zero");

    let result = ctx
        .consensus
        .assert_can_build_block(0, nonzero_hash(9), false);

    assert_result_err_contains(result, "height=0");
}

#[test]
fn blockchainconsensus_39_edge_assert_can_build_block_rejects_zero_prev_hash() {
    let mut ctx = must_ctx("edge_assert_can_build_block_rejects_zero_prev_hash");

    let result = ctx.consensus.assert_can_build_block(1, [0u8; 64], false);

    assert_result_err_contains(result, "zero prev_hash");
}

#[test]
fn blockchainconsensus_40_adversarial_assert_can_build_block_rejects_unknown_parent_hash() {
    let mut ctx = must_ctx("adversarial_assert_can_build_block_rejects_unknown_parent_hash");

    let result = ctx
        .consensus
        .assert_can_build_block(1, nonzero_hash(99), false);

    assert_result_err_contains(result, "parent hash is not known");
}

#[test]
fn blockchainconsensus_41_vector_register_node_tx_new_accepts_canonical_wallet() {
    let wallet = wallet_from_seed(41);

    let tx = match RegisterNodeTx::new(wallet.clone()) {
        Ok(tx) => tx,
        Err(err) => panic!("RegisterNodeTx::new failed: {err:?}"),
    };

    let wallet_str = match tx.wallet_str() {
        Ok(s) => s,
        Err(err) => panic!("wallet_str failed: {err:?}"),
    };

    assert_eq!(wallet_str, wallet.as_str());
    assert!(tx.validate().is_ok());
}

#[test]
fn blockchainconsensus_42_vector_register_node_tx_new_from_bytes_accepts_canonical_bytes() {
    let wallet = wallet_from_seed(42);

    let tx = match RegisterNodeTx::new_from_bytes(wallet.as_bytes()) {
        Ok(tx) => tx,
        Err(err) => panic!("new_from_bytes failed: {err:?}"),
    };

    let wallet_str = match tx.wallet_str() {
        Ok(s) => s,
        Err(err) => panic!("wallet_str failed: {err:?}"),
    };

    assert_eq!(wallet_str, wallet.as_str());
}

#[test]
fn blockchainconsensus_43_vector_register_node_tx_roundtrip_serialization() {
    let wallet = wallet_from_seed(43);

    let tx = match RegisterNodeTx::new(wallet) {
        Ok(tx) => tx,
        Err(err) => panic!("RegisterNodeTx::new failed: {err:?}"),
    };

    let encoded = match tx.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("serialize failed: {err:?}"),
    };

    let decoded = match RegisterNodeTx::deserialize(&encoded) {
        Ok(tx) => tx,
        Err(err) => panic!("deserialize failed: {err:?}"),
    };

    assert_eq!(decoded, tx);
    assert!(decoded.validate().is_ok());
}

#[test]
fn blockchainconsensus_44_edge_register_node_tx_rejects_short_wallet() {
    let result = RegisterNodeTx::new("rabc".to_owned());

    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchainconsensus_45_edge_register_node_tx_rejects_bad_hex_wallet() {
    let wallet = format!("r{}", "g".repeat(128));
    let result = RegisterNodeTx::new(wallet);

    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchainconsensus_46_edge_register_node_tx_rejects_embedded_nul_bytes() {
    let mut wallet_bytes = wallet_from_seed(46).into_bytes();

    match wallet_bytes.get_mut(10) {
        Some(byte) => *byte = 0,
        None => panic!("wallet byte index missing"),
    }

    let result = RegisterNodeTx::new_from_bytes(&wallet_bytes);

    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchainconsensus_47_fuzz_register_node_tx_rejects_corrupt_postcard_payloads() {
    let payloads: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0],
        vec![1, 2, 3, 4],
        vec![255; 8],
        vec![17; 128],
    ];

    for payload in payloads {
        let result = RegisterNodeTx::deserialize(&payload);
        assert!(result.is_err());
    }
}

#[test]
fn blockchainconsensus_48_property_register_node_tx_wallet_str_matches_input_for_many_wallets() {
    for seed in 0u8..16u8 {
        let wallet = wallet_from_seed(seed);

        let tx = match RegisterNodeTx::new(wallet.clone()) {
            Ok(tx) => tx,
            Err(err) => panic!("RegisterNodeTx::new failed for seed {seed}: {err:?}"),
        };

        let wallet_str = match tx.wallet_str() {
            Ok(s) => s,
            Err(err) => panic!("wallet_str failed for seed {seed}: {err:?}"),
        };

        assert_eq!(wallet_str, wallet.as_str());
    }
}

#[test]
fn blockchainconsensus_49_vector_puzzle_pool_records_one_success() {
    let mut pool = PorPuzzlePool::new();
    let wallet = wallet_from_seed(49);

    match pool.record_success_checked(7, &wallet, 123) {
        Ok(()) => {}
        Err(err) => panic!("record_success_checked failed: {err:?}"),
    }

    assert_eq!(pool.winners_for_height(7), vec![wallet]);
    assert!(pool.entropy_for_height(7).is_some());
}

#[test]
fn blockchainconsensus_50_vector_puzzle_pool_overwrites_same_wallet_output_without_duplicate() {
    let mut pool = PorPuzzlePool::new();
    let wallet = wallet_from_seed(50);

    match pool.record_success_checked(8, &wallet, 111) {
        Ok(()) => {}
        Err(err) => panic!("first record failed: {err:?}"),
    }

    match pool.record_success_checked(8, &wallet, 222) {
        Ok(()) => {}
        Err(err) => panic!("second record failed: {err:?}"),
    }

    assert_eq!(pool.winners_for_height(8), vec![wallet]);
    assert!(pool.entropy_for_height(8).is_some());
}

#[test]
fn blockchainconsensus_51_property_puzzle_pool_winners_are_sorted_deterministically() {
    let mut pool = PorPuzzlePool::new();

    let w3 = wallet_with_hex_char('3');
    let w1 = wallet_with_hex_char('1');
    let w2 = wallet_with_hex_char('2');

    for (wallet, output) in [
        (w3.clone(), 3u128),
        (w1.clone(), 1u128),
        (w2.clone(), 2u128),
    ] {
        match pool.record_success_checked(9, &wallet, output) {
            Ok(()) => {}
            Err(err) => panic!("record failed: {err:?}"),
        }
    }

    assert_eq!(pool.winners_for_height(9), vec![w1, w2, w3]);
}

#[test]
fn blockchainconsensus_52_property_puzzle_pool_entropy_is_order_independent() {
    let mut first = PorPuzzlePool::new();
    let mut second = PorPuzzlePool::new();

    let w1 = wallet_from_seed(1);
    let w2 = wallet_from_seed(2);
    let w3 = wallet_from_seed(3);

    for (wallet, output) in [
        (w1.clone(), 10u128),
        (w2.clone(), 20u128),
        (w3.clone(), 30u128),
    ] {
        match first.record_success_checked(10, &wallet, output) {
            Ok(()) => {}
            Err(err) => panic!("first pool record failed: {err:?}"),
        }
    }

    for (wallet, output) in [(w3, 30u128), (w1, 10u128), (w2, 20u128)] {
        match second.record_success_checked(10, &wallet, output) {
            Ok(()) => {}
            Err(err) => panic!("second pool record failed: {err:?}"),
        }
    }

    assert_eq!(first.entropy_for_height(10), second.entropy_for_height(10));
}

#[test]
fn blockchainconsensus_53_edge_puzzle_pool_rejects_invalid_wallet() {
    let mut pool = PorPuzzlePool::new();

    let result = pool.record_success_checked(11, "not-a-wallet", 1);

    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchainconsensus_54_edge_puzzle_pool_rejects_overlong_wallet_string() {
    let mut pool = PorPuzzlePool::new();
    let overlong = "r".repeat(257);

    let result = pool.record_success_checked(12, &overlong, 1);

    assert_result_err_contains(result, "too long");
}

#[test]
fn blockchainconsensus_55_vector_puzzle_pool_gc_below_removes_old_heights() {
    let mut pool = PorPuzzlePool::new();
    let wallet = wallet_from_seed(55);

    for height in 1u64..=5u64 {
        match pool.record_success_checked(height, &wallet, u128::from(height)) {
            Ok(()) => {}
            Err(err) => panic!("record failed at height {height}: {err:?}"),
        }
    }

    pool.gc_below(4);

    assert!(pool.winners_for_height(1).is_empty());
    assert!(pool.winners_for_height(2).is_empty());
    assert!(pool.winners_for_height(3).is_empty());
    assert!(!pool.winners_for_height(4).is_empty());
    assert!(!pool.winners_for_height(5).is_empty());
}

#[test]
fn blockchainconsensus_56_load_puzzle_pool_records_many_heights() {
    let mut pool = PorPuzzlePool::new();
    let wallet = wallet_from_seed(56);

    for height in 1u64..=64u64 {
        match pool.record_success_checked(height, &wallet, u128::from(height) + 100) {
            Ok(()) => {}
            Err(err) => panic!("record failed at height {height}: {err:?}"),
        }
    }

    for height in 1u64..=64u64 {
        assert_eq!(pool.winners_for_height(height).len(), 1);
        assert!(pool.entropy_for_height(height).is_some());
    }
}

#[test]
fn blockchainconsensus_57_vector_block_puzzle_proof_from_gossip_roundtrip() {
    let wallet = wallet_from_seed(57);
    let prev = nonzero_hash(57);
    let gossip = valid_gossip_proof_for_extra_tests(&wallet, 57, prev);

    let block_proof = match BlockPuzzleProof::from_gossip(&gossip) {
        Ok(proof) => proof,
        Err(err) => panic!("from_gossip failed: {err:?}"),
    };

    let roundtrip = block_proof.to_gossip();

    assert_eq!(roundtrip.height, gossip.height);
    assert_eq!(roundtrip.validator, gossip.validator);
    assert_eq!(roundtrip.prev_block_hash, gossip.prev_block_hash);
    assert_eq!(roundtrip.output, gossip.output);
}

#[test]
fn blockchainconsensus_58_vector_block_puzzle_proof_verifies_with_engine() {
    let wallet = wallet_from_seed(58);
    let prev = nonzero_hash(58);
    let engine = PorPuzzleEngine::from_globals();
    let proof = must_block_puzzle_proof(&wallet, 58, prev);

    let ok = match proof.verify_with_engine_checked(&engine) {
        Ok(v) => v,
        Err(err) => panic!("verify_with_engine_checked failed: {err:?}"),
    };

    assert!(ok);
    assert!(proof.verify_with_engine(&engine));
}

#[test]
fn blockchainconsensus_59_edge_block_puzzle_proof_rejects_zero_prev_hash() {
    let wallet = wallet_from_seed(59);

    let result = BlockPuzzleProof::new(59, wallet, [0u8; 64], 1);

    assert_result_err_contains(result, "sentinel");
}

#[test]
fn blockchainconsensus_60_edge_block_puzzle_proof_rejects_ff_prev_hash() {
    let wallet = wallet_from_seed(60);

    let result = BlockPuzzleProof::new(60, wallet, [0xFFu8; 64], 1);

    assert_result_err_contains(result, "sentinel");
}

#[test]
fn blockchainconsensus_61_edge_block_puzzle_proof_rejects_zero_output() {
    let wallet = wallet_from_seed(61);

    let result = BlockPuzzleProof::new(61, wallet, nonzero_hash(61), 0);

    assert_result_err_contains(result, "output");
}

#[test]
fn blockchainconsensus_62_edge_block_puzzle_proof_rejects_height_out_of_bounds() {
    let wallet = wallet_from_seed(62);

    let result = BlockPuzzleProof::new(10_000_001, wallet, nonzero_hash(62), 1);

    assert_result_err_contains(result, "height");
}

#[test]
fn blockchainconsensus_63_vector_block_puzzle_proof_commitment_is_64_bytes_and_128_hex() {
    let wallet = wallet_from_seed(63);
    let proof = must_block_puzzle_proof(&wallet, 63, nonzero_hash(63));

    let bytes = match proof.commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("commitment_bytes failed: {err:?}"),
    };

    let hex = match proof.commitment_hex() {
        Ok(hex) => hex,
        Err(err) => panic!("commitment_hex failed: {err:?}"),
    };

    assert_eq!(bytes.len(), 64);
    assert_eq!(hex.len(), 128);
}

#[test]
fn blockchainconsensus_64_property_block_puzzle_proof_commitment_is_stable() {
    let wallet = wallet_from_seed(64);
    let proof = must_block_puzzle_proof(&wallet, 64, nonzero_hash(64));

    let first = match proof.commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("first commitment failed: {err:?}"),
    };

    let second = match proof.commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("second commitment failed: {err:?}"),
    };

    assert_eq!(first, second);
}

#[test]
fn blockchainconsensus_65_vector_block_metadata_without_puzzle_proof_has_zero_commitment() {
    let meta = valid_metadata_for_extra_tests(None);

    let commitment = match meta.puzzle_commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("puzzle_commitment_bytes failed: {err:?}"),
    };

    assert_eq!(commitment, [0u8; 64]);
}

#[test]
fn blockchainconsensus_66_vector_block_metadata_with_puzzle_proof_has_nonzero_commitment() {
    let wallet = wallet_from_seed(66);
    let proof = must_block_puzzle_proof(&wallet, 66, nonzero_hash(66));
    let meta = valid_metadata_for_extra_tests(Some(proof));

    let commitment = match meta.puzzle_commitment_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("puzzle_commitment_bytes failed: {err:?}"),
    };

    assert_ne!(commitment, [0u8; 64]);
}

#[test]
fn blockchainconsensus_67_vector_block_metadata_puzzle_commitment_hex_is_128_chars() {
    let wallet = wallet_from_seed(67);
    let proof = must_block_puzzle_proof(&wallet, 67, nonzero_hash(67));
    let meta = valid_metadata_for_extra_tests(Some(proof));

    let hex = match meta.puzzle_commitment_hex() {
        Ok(hex) => hex,
        Err(err) => panic!("puzzle_commitment_hex failed: {err:?}"),
    };

    assert_eq!(hex.len(), 128);
}

#[test]
fn blockchainconsensus_68_vector_por_consensus_config_from_globals_validates() {
    let cfg = PorConsensusConfig::from_globals();

    assert!(cfg.validate().is_ok());
    assert_eq!(cfg.puzzle_kind, PorPuzzleKind::FibonacciDelayDev);
    assert!(cfg.target_block_time.as_secs() >= 1);
    assert!(cfg.max_local_puzzle_ms >= 1_000);
}

#[test]
fn blockchainconsensus_69_edge_por_consensus_config_rejects_zero_target_time() {
    let mut cfg = PorConsensusConfig::from_globals();
    cfg.target_block_time = std::time::Duration::from_secs(0);

    let result = cfg.validate();

    assert_result_err_contains(result, "target_block_time");
}

#[test]
fn blockchainconsensus_70_edge_por_consensus_config_rejects_zero_soft_cap() {
    let mut cfg = PorConsensusConfig::from_globals();
    cfg.max_local_puzzle_ms = 0;

    let result = cfg.validate();

    assert_result_err_contains(result, "max_local_puzzle_ms");
}

#[test]
fn blockchainconsensus_71_edge_por_consensus_config_rejects_wrong_puzzle_kind() {
    let mut cfg = PorConsensusConfig::from_globals();
    cfg.puzzle_kind = PorPuzzleKind::FactorizationDelayDev;

    let result = cfg.validate();

    assert_result_err_contains(result, "puzzle_kind");
}

#[test]
fn blockchainconsensus_72_vector_leader_schedule_new_canonicalizes_wallet() {
    let wallet = wallet_from_seed(72);

    let schedule = match LeaderSchedule::new(wallet.clone()) {
        Ok(schedule) => schedule,
        Err(err) => panic!("LeaderSchedule::new failed: {err:?}"),
    };

    assert_eq!(schedule.local_wallet(), wallet.as_str());
}

#[test]
fn blockchainconsensus_73_edge_leader_schedule_new_rejects_invalid_wallet() {
    let result = LeaderSchedule::new("bad-wallet".to_owned());

    assert_result_err_contains(result, "wallet");
}

#[test]
fn blockchainconsensus_74_property_committee_hash_is_deterministic() {
    let validators = vec![
        wallet_from_seed(1),
        wallet_from_seed(2),
        wallet_from_seed(3),
    ];
    let parent = nonzero_hash(74);

    let first = LeaderSchedule::compute_committee_hash(parent, 74, 4, &validators);
    let second = LeaderSchedule::compute_committee_hash(parent, 74, 4, &validators);

    assert_eq!(first, second);
}

#[test]
fn blockchainconsensus_75_property_committee_hash_changes_when_parent_changes() {
    let validators = vec![
        wallet_from_seed(1),
        wallet_from_seed(2),
        wallet_from_seed(3),
    ];

    let first = LeaderSchedule::compute_committee_hash(nonzero_hash(75), 75, 4, &validators);
    let second = LeaderSchedule::compute_committee_hash(nonzero_hash(76), 75, 4, &validators);

    assert_ne!(first, second);
}

#[test]
fn blockchainconsensus_76_property_leader_score_is_deterministic() {
    let wallet = wallet_from_seed(76);
    let parent = nonzero_hash(76);
    let committee_hash = nonzero_hash(77);

    let first = LeaderSchedule::leader_score(committee_hash, parent, 76, 0, &wallet);
    let second = LeaderSchedule::leader_score(committee_hash, parent, 76, 0, &wallet);

    assert_eq!(first, second);
}

#[test]
fn blockchainconsensus_77_vector_leader_for_round_selects_member_from_snapshot() {
    let validators = vec![
        wallet_from_seed(1),
        wallet_from_seed(2),
        wallet_from_seed(3),
    ];
    let parent = nonzero_hash(77);
    let committee_hash = LeaderSchedule::compute_committee_hash(parent, 77, 4, &validators);

    let snapshot = CommitteeSnapshot {
        height: 77,
        parent_hash: parent,
        activation_delay_blocks: 4,
        validators: validators.clone(),
        committee_hash,
    };

    let decision = match LeaderSchedule::leader_for_round(&snapshot, 0) {
        Ok(decision) => decision,
        Err(err) => panic!("leader_for_round failed: {err:?}"),
    };

    assert!(validators.iter().any(|wallet| wallet == &decision.leader));
    assert_eq!(decision.height, 77);
    assert_eq!(decision.round, 0);
    assert_eq!(decision.committee_len, validators.len());
}

#[test]
fn blockchainconsensus_78_edge_leader_for_round_rejects_height_zero_snapshot() {
    let validators = vec![wallet_from_seed(1)];
    let parent = nonzero_hash(78);
    let committee_hash = LeaderSchedule::compute_committee_hash(parent, 0, 4, &validators);

    let snapshot = CommitteeSnapshot {
        height: 0,
        parent_hash: parent,
        activation_delay_blocks: 4,
        validators,
        committee_hash,
    };

    let result = LeaderSchedule::leader_for_round(&snapshot, 0);

    assert_result_err_contains(result, "height=0");
}

#[test]
fn blockchainconsensus_79_vector_validator_lifecycle_apply_register_insert_renew_exit_reactivate() {
    let wallet = wallet_from_seed(79);
    let mut map = std::collections::BTreeMap::new();

    let inserted =
        match ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet, 10, 1_700_000_000) {
            Ok(outcome) => outcome,
            Err(err) => panic!("insert failed: {err:?}"),
        };

    assert_eq!(inserted, RegisterOutcome::Inserted);
    assert_eq!(map.len(), 1);

    let renewed =
        match ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet, 11, 1_700_000_001) {
            Ok(outcome) => outcome,
            Err(err) => panic!("renew failed: {err:?}"),
        };

    assert_eq!(renewed, RegisterOutcome::Renewed);

    let exited = match ValidatorLifecycle::apply_exit(&mut map, &wallet, 12) {
        Ok(changed) => changed,
        Err(err) => panic!("exit failed: {err:?}"),
    };

    assert!(exited);

    let reactivated =
        match ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet, 13, 1_700_000_002) {
            Ok(outcome) => outcome,
            Err(err) => panic!("reactivate failed: {err:?}"),
        };

    assert_eq!(reactivated, RegisterOutcome::Reactivated);
}

#[test]
fn blockchainconsensus_80_load_validator_lifecycle_registers_many_validators() {
    let mut map = std::collections::BTreeMap::new();

    for seed in 0u8..40u8 {
        let wallet = wallet_from_seed(seed);
        let height = u64::from(seed).saturating_add(1);
        let timestamp = 1_700_000_000u64.saturating_add(u64::from(seed));

        let outcome =
            match ValidatorLifecycle::apply_register_or_renew(&mut map, &wallet, height, timestamp)
            {
                Ok(outcome) => outcome,
                Err(err) => panic!("register failed for seed {seed}: {err:?}"),
            };

        assert_eq!(outcome, RegisterOutcome::Inserted);
    }

    assert_eq!(map.len(), 40);

    let cfg = ValidatorLifecycleConfig::from_globals();
    assert!(cfg.validate().is_ok());

    for (wallet, meta) in &map {
        assert!(meta.validate_invariants(wallet).is_ok());
    }
}

#[test]
fn blockchainconsensus_81_edge_set_registry_replaces_old_live_wallets() {
    let mut ctx = must_ctx("edge_set_registry_replaces_old_live_wallets");
    let old_wallet = ctx.local_wallet.clone();
    let new_wallet = wallet_u64(81);

    ctx.consensus
        .set_registry(must_registry(std::slice::from_ref(&old_wallet)));
    assert!(
        ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&old_wallet)
    );

    ctx.consensus
        .set_registry(must_registry(std::slice::from_ref(&new_wallet)));
    assert!(
        !ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&old_wallet)
    );
    assert!(
        ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&new_wallet)
    );
}

#[test]
fn blockchainconsensus_82_edge_set_registry_empty_clears_live_wallets() {
    let mut ctx = must_ctx("edge_set_registry_empty_clears_live_wallets");

    ctx.consensus
        .set_registry(must_registry(&[ctx.local_wallet.clone()]));
    assert!(
        ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&ctx.local_wallet)
    );

    ctx.consensus.set_registry(RegistryData::new());

    assert!(
        !ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&ctx.local_wallet)
    );
    assert!(
        ctx.consensus
            .collect_register_node_txs_for_block(1)
            .is_empty()
    );
}

#[test]
fn blockchainconsensus_83_property_collect_register_node_txs_returns_sorted_wallets() {
    let mut ctx = must_ctx("property_collect_register_node_txs_returns_sorted_wallets");

    let w3 = wallet_u64(103);
    let w1 = wallet_u64(101);
    let w2 = wallet_u64(102);

    ctx.consensus
        .set_registry(must_registry(&[w3.clone(), w1.clone(), w2.clone()]));

    let txs = ctx.consensus.collect_register_node_txs_for_block(1);
    let wallets: Vec<String> = txs.iter().map(wallet_str_from_register_tx).collect();

    assert_eq!(wallets, vec![w1, w2, w3]);
}

#[test]
fn blockchainconsensus_84_edge_collect_register_node_txs_skips_only_canonical_known_wallets() {
    let mut ctx = must_ctx("edge_collect_register_node_txs_skips_only_canonical_known_wallets");

    let known = ctx.local_wallet.clone();
    let unknown = wallet_u64(84);

    match ctx
        .consensus
        .validator_state_mut()
        .seed_genesis_founder(&known, 1_700_000_000)
    {
        Ok(()) => {}
        Err(err) => panic!("seed_genesis_founder failed: {err:?}"),
    }

    ctx.consensus
        .set_registry(must_registry(&[known.clone(), unknown.clone()]));

    let txs = ctx.consensus.collect_register_node_txs_for_block(1);
    let wallets: Vec<String> = txs.iter().map(wallet_str_from_register_tx).collect();

    assert_eq!(wallets, vec![unknown]);
}

#[test]
fn blockchainconsensus_85_vector_pending_buffer_count_for_absent_parent_is_zero() {
    let ctx = must_ctx("vector_pending_buffer_count_for_absent_parent_is_zero");

    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(nonzero_hash(85)),
        0
    );
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_86_adversarial_tampered_valid_shape_puzzle_proof_is_rejected() {
    let mut ctx = must_ctx("adversarial_tampered_valid_shape_puzzle_proof_is_rejected");
    let prev = nonzero_hash(86);

    let mut proof = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 86, prev);
    proof.output = proof.output.saturating_add(1);

    assert!(!ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_87_adversarial_multiple_unknown_parent_proofs_are_counted_by_parent() {
    let mut ctx = must_ctx("adversarial_multiple_unknown_parent_proofs_are_counted_by_parent");

    let parent_a = nonzero_hash(87);
    let parent_b = nonzero_hash(88);

    let proof_a = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 87, parent_a);
    let proof_b = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 88, parent_b);

    assert!(ctx.consensus.on_puzzle_proof(&proof_a));
    assert!(ctx.consensus.on_puzzle_proof(&proof_b));

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 2);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(parent_a),
        1
    );
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(parent_b),
        1
    );
}

#[test]
fn blockchainconsensus_88_edge_gc_puzzle_pool_below_retains_equal_height_buffered_proof() {
    let mut ctx = must_ctx("edge_gc_puzzle_pool_below_retains_equal_height_buffered_proof");
    let parent = nonzero_hash(89);
    let proof = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 89, parent);

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    ctx.consensus.gc_puzzle_pool_below(89);

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
}

#[test]
fn blockchainconsensus_89_edge_gc_puzzle_pool_below_removes_lower_height_buffered_proof() {
    let mut ctx = must_ctx("edge_gc_puzzle_pool_below_removes_lower_height_buffered_proof");
    let parent = nonzero_hash(90);
    let proof = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 90, parent);

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    ctx.consensus.gc_puzzle_pool_below(91);

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_90_vector_reward_eligible_at_false_for_unknown_wallet() {
    let ctx = must_ctx("vector_reward_eligible_at_false_for_unknown_wallet");
    let unknown = wallet_u64(90);

    assert!(!ctx.consensus.reward_eligible_at(&unknown, 100));
}

#[test]
fn blockchainconsensus_91_vector_reward_eligible_at_true_for_seeded_founder() {
    let mut ctx = must_ctx("vector_reward_eligible_at_true_for_seeded_founder");

    match ctx
        .consensus
        .validator_state_mut()
        .seed_genesis_founder(&ctx.local_wallet, 1_700_000_000)
    {
        Ok(()) => {}
        Err(err) => panic!("seed_genesis_founder failed: {err:?}"),
    }

    assert!(ctx.consensus.reward_eligible_at(&ctx.local_wallet, 0));
    assert!(ctx.consensus.reward_eligible_at(&ctx.local_wallet, 100));
}

#[test]
fn blockchainconsensus_92_edge_clear_runtime_canonical_tip_context_is_idempotent() {
    let mut ctx = must_ctx("edge_clear_runtime_canonical_tip_context_is_idempotent");

    ctx.consensus.clear_runtime_canonical_tip_context();
    ctx.consensus.clear_runtime_canonical_tip_context();

    assert_eq!(ctx.consensus.validator_state_rebuilt_at_tip(), Some(0));
}

#[test]
fn blockchainconsensus_93_vector_runtime_tip_context_reset_then_clear_keeps_rebuild_marker() {
    let mut ctx = must_ctx("vector_runtime_tip_context_reset_then_clear_keeps_rebuild_marker");

    ctx.consensus
        .reset_runtime_proposal_safety_state(93, nonzero_hash(93));
    ctx.consensus.clear_runtime_canonical_tip_context();

    assert_eq!(ctx.consensus.validator_state_rebuilt_at_tip(), Some(93));
    assert!(!ctx.consensus.runtime_rejoin_catchup_gate_active());
    assert!(!ctx.consensus.runtime_branch_hydration_active());
}

#[test]
fn blockchainconsensus_94_edge_assert_can_build_block_prioritizes_bypass_before_zero_height() {
    let mut ctx = must_ctx("edge_assert_can_build_block_prioritizes_bypass_before_zero_height");

    let result = ctx.consensus.assert_can_build_block(0, [0u8; 64], true);

    assert_result_err_contains(result, "bypass_leader");
}

#[test]
fn blockchainconsensus_95_edge_assert_can_build_block_prioritizes_height_before_zero_prev_hash() {
    let mut ctx = must_ctx("edge_assert_can_build_block_prioritizes_height_before_zero_prev_hash");

    let result = ctx.consensus.assert_can_build_block(0, [0u8; 64], false);

    assert_result_err_contains(result, "height=0");
}

#[test]
fn blockchainconsensus_96_edge_register_node_tx_accepts_trailing_nul_padding() {
    let wallet = wallet_u64(96);
    let mut bytes = wallet.as_bytes().to_vec();

    // Production RegisterNodeTx::new_from_bytes trims trailing NUL padding.
    bytes.extend_from_slice(&[0u8; 8]);

    let tx = match RegisterNodeTx::new_from_bytes(&bytes) {
        Ok(tx) => tx,
        Err(err) => {
            panic!("RegisterNodeTx::new_from_bytes should accept trailing NUL padding: {err:?}")
        }
    };

    let wallet_str = match tx.wallet_str() {
        Ok(s) => s.to_owned(),
        Err(err) => panic!("wallet_str failed after trailing NUL canonicalization: {err:?}"),
    };

    assert_eq!(wallet_str, wallet);
    assert!(tx.validate().is_ok());
}

#[test]
fn blockchainconsensus_97_edge_register_node_tx_validate_rejects_too_old_timestamp() {
    let wallet = wallet_u64(97);

    let mut tx = match RegisterNodeTx::new(wallet) {
        Ok(tx) => tx,
        Err(err) => panic!("RegisterNodeTx::new failed: {err:?}"),
    };

    tx.timestamp = 1;

    let result = tx.validate();
    assert_result_err_contains(result, "Timestamp");
}

#[test]
fn blockchainconsensus_98_edge_register_node_tx_validate_rejects_absurd_future_timestamp() {
    let wallet = wallet_u64(98);

    let mut tx = match RegisterNodeTx::new(wallet) {
        Ok(tx) => tx,
        Err(err) => panic!("RegisterNodeTx::new failed: {err:?}"),
    };

    tx.timestamp = u64::MAX;

    let result = tx.validate();
    assert_result_err_contains(result, "Timestamp");
}

#[test]
fn blockchainconsensus_99_edge_register_node_tx_deserialize_rejects_tampered_old_timestamp() {
    let wallet = wallet_u64(99);

    let mut tx = match RegisterNodeTx::new(wallet) {
        Ok(tx) => tx,
        Err(err) => panic!("RegisterNodeTx::new failed: {err:?}"),
    };

    tx.timestamp = 2;

    let encoded = match postcard::to_allocvec(&tx) {
        Ok(bytes) => bytes,
        Err(err) => panic!("raw postcard serialization failed: {err:?}"),
    };

    let result = RegisterNodeTx::deserialize(&encoded);

    assert_result_err_contains(result, "timestamp below");
}

#[test]
fn blockchainconsensus_100_edge_block_puzzle_proof_structural_rejects_noncanonical_validator() {
    let proof = BlockPuzzleProof {
        height: 100,
        validator: format!("r{}", "A".repeat(128)),
        prev_block_hash: nonzero_hash(100),
        output: 1,
    };

    let result = proof.validate_structural();
    assert_result_err_contains(result, "canonical");
}

#[test]
fn blockchainconsensus_101_adversarial_block_puzzle_proof_verify_returns_false_for_tampered_output()
{
    let wallet = wallet_u64(101);
    let prev = nonzero_hash(101);
    let engine = PorPuzzleEngine::from_globals();

    let mut proof = must_block_puzzle_proof(&wallet, 101, prev);
    proof.output = proof.output.saturating_add(1);

    let ok = match proof.verify_with_engine_checked(&engine) {
        Ok(v) => v,
        Err(err) => panic!("verify_with_engine_checked returned error: {err:?}"),
    };

    assert!(!ok);
    assert!(!proof.verify_with_engine(&engine));
}

#[test]
fn blockchainconsensus_102_property_block_puzzle_proof_commitment_changes_when_output_changes() {
    let wallet = wallet_u64(102);
    let prev = nonzero_hash(102);

    let first = match BlockPuzzleProof::new(102, wallet.clone(), prev, 1) {
        Ok(proof) => proof,
        Err(err) => panic!("first proof failed: {err:?}"),
    };

    let second = match BlockPuzzleProof::new(102, wallet, prev, 2) {
        Ok(proof) => proof,
        Err(err) => panic!("second proof failed: {err:?}"),
    };

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
fn blockchainconsensus_103_vector_block_metadata_to_bytes_from_bytes_roundtrip() {
    let meta = valid_metadata_for_extra_tests(None);

    let encoded = match meta.to_bytes() {
        Ok(bytes) => bytes,
        Err(err) => panic!("BlockMetadata::to_bytes failed: {err:?}"),
    };

    let decoded = match BlockMetadata::from_bytes(&encoded) {
        Ok(meta) => meta,
        Err(err) => panic!("BlockMetadata::from_bytes failed: {err:?}"),
    };

    assert_eq!(decoded, meta);
}

#[test]
fn blockchainconsensus_104_edge_block_metadata_rejects_non_genesis_zero_previous_hash() {
    let mut meta = valid_metadata_for_extra_tests(None);
    meta.previous_hash = [0u8; 64];

    let result = meta.validate_structural();
    assert_result_err_contains(result, "previous_hash");
}

#[test]
fn blockchainconsensus_105_edge_block_metadata_rejects_zero_merkle_root() {
    let mut meta = valid_metadata_for_extra_tests(None);
    meta.merkle_root = [0u8; 64];

    let result = meta.validate_structural();
    assert_result_err_contains(result, "merkle_root");
}

#[test]
fn blockchainconsensus_106_edge_block_metadata_rejects_zero_guardian_signature_non_genesis() {
    let mut meta = valid_metadata_for_extra_tests(None);
    meta.guardian_signature = [0u8; ml_dsa_65::SIG_LEN];

    let result = meta.validate_structural();
    assert_result_err_contains(result, "guardian_signature");
}

#[test]
fn blockchainconsensus_107_edge_block_metadata_rejects_merkle_equal_previous_hash() {
    let mut meta = valid_metadata_for_extra_tests(None);
    meta.merkle_root = meta.previous_hash;

    let result = meta.validate_structural();
    assert_result_err_contains(result, "merkle_root == previous_hash");
}

#[test]
fn blockchainconsensus_108_edge_block_metadata_rejects_puzzle_proof_height_mismatch() {
    let wallet = wallet_u64(108);
    let proof = must_block_puzzle_proof(&wallet, 108, nonzero_hash(21));
    let meta = valid_metadata_for_extra_tests(Some(proof));

    let result = meta.validate_structural();
    assert_result_err_contains(result, "puzzle_proof.height");
}

#[test]
fn blockchainconsensus_109_edge_block_metadata_rejects_puzzle_proof_prev_hash_mismatch() {
    let wallet = wallet_u64(109);
    let proof = must_block_puzzle_proof(&wallet, 5, nonzero_hash(109));
    let meta = valid_metadata_for_extra_tests(Some(proof));

    let result = meta.validate_structural();
    assert_result_err_contains(result, "puzzle_proof.prev_block_hash");
}

#[test]
fn blockchainconsensus_110_edge_block_metadata_rejects_genesis_with_puzzle_proof() {
    let wallet = wallet_u64(110);
    let proof = must_block_puzzle_proof(&wallet, 0, nonzero_hash(110));

    let meta = BlockMetadata::new(
        0,
        1_700_000_000,
        [0u8; 64],
        nonzero_hash(22),
        [0u8; ml_dsa_65::SIG_LEN],
        Some(proof),
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    let result = meta.validate_structural();
    assert_result_err_contains(result, "genesis must not include puzzle_proof");
}

#[test]
fn blockchainconsensus_111_vector_leader_schedule_round_for_height_from_timestamp_at_start() {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));
    let height = 3;
    let observed = LeaderSchedule::height_start_unix(&tm, height);

    let (round, elapsed, in_round, round_start) =
        match LeaderSchedule::round_for_height_from_timestamp(&tm, height, observed) {
            Ok(v) => v,
            Err(err) => panic!("round_for_height_from_timestamp failed: {err:?}"),
        };

    assert_eq!(round, 0);
    assert_eq!(elapsed, 0);
    assert_eq!(in_round, 0);
    assert_eq!(round_start, observed);
}

#[test]
fn blockchainconsensus_112_vector_leader_schedule_round_advances_after_tau() {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));
    let height = 4;
    let start = LeaderSchedule::height_start_unix(&tm, height);
    let observed = start.saturating_add(tm.failover_window_secs());

    let (round, elapsed, in_round, _round_start) =
        match LeaderSchedule::round_for_height_from_timestamp(&tm, height, observed) {
            Ok(v) => v,
            Err(err) => panic!("round_for_height_from_timestamp failed: {err:?}"),
        };

    assert_eq!(round, 1);
    assert_eq!(elapsed, tm.failover_window_secs());
    assert_eq!(in_round, 0);
}

#[test]
fn blockchainconsensus_113_edge_leader_schedule_round_for_timestamp_rejects_height_zero() {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));

    let result = LeaderSchedule::round_for_height_from_timestamp(&tm, 0, 1_700_000_000);

    assert_result_err_contains(result, "height=0");
}

#[test]
fn blockchainconsensus_114_edge_leader_schedule_round_for_timestamp_rejects_too_early() {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));
    let height = 10;
    let start = LeaderSchedule::height_start_unix(&tm, height);
    let observed = start.saturating_sub(1);

    let result = LeaderSchedule::round_for_height_from_timestamp(&tm, height, observed);

    assert_result_err_contains(result, "earlier than nominal start");
}

#[test]
fn blockchainconsensus_115_edge_leader_schedule_round_for_now_rejects_before_drift_window() {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));
    let height = 10;
    let start = LeaderSchedule::height_start_unix(&tm, height);
    let drift = tm.slot_gate_drift_secs();
    let now = start.saturating_sub(drift.saturating_add(1));

    let result = LeaderSchedule::round_for_height_now(&tm, height, now);

    assert_result_err_contains(result, "too early");
}

#[test]
fn blockchainconsensus_116_vector_leader_schedule_within_slot_proposal_window_accepts_start() {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));

    let result = LeaderSchedule::ensure_within_slot_proposal_window(&tm, 0);

    assert!(result.is_ok());
}

#[test]
fn blockchainconsensus_117_edge_leader_schedule_within_slot_proposal_window_rejects_deadline() {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));
    let elapsed = tm.proposal_deadline_secs();

    let result = LeaderSchedule::ensure_within_slot_proposal_window(&tm, elapsed);

    assert_result_err_contains(result, "too late in slot");
}

#[test]
fn blockchainconsensus_118_edge_leader_schedule_enough_time_in_round_rejects_late_round() {
    let tm = TimeManager::new(TimeConfig::from_genesis_ts(1_700_000_000));
    let late = tm.failover_window_secs().saturating_sub(1);

    let result = LeaderSchedule::ensure_enough_time_in_round_for_local_puzzle(&tm, late);

    assert_result_err_contains(result, "too late in round");
}

#[test]
fn blockchainconsensus_119_vector_validator_meta_founder_is_active_proposable_and_reward_eligible()
{
    let cfg = ValidatorLifecycleConfig::from_globals();

    let meta = match ValidatorMeta::founder(1_700_000_000) {
        Ok(meta) => meta,
        Err(err) => panic!("ValidatorMeta::founder failed: {err:?}"),
    };

    assert!(meta.is_active_at(0, cfg));
    assert!(meta.is_proposable_at(0, cfg));
    assert!(meta.reward_eligible_at(0, cfg));
}

#[test]
fn blockchainconsensus_120_load_validator_lifecycle_renew_many_validators_monotonically() {
    let mut map = std::collections::BTreeMap::new();

    for seed in 0u64..32u64 {
        let wallet = wallet_u64(seed);
        let inserted = match ValidatorLifecycle::apply_register_or_renew(
            &mut map,
            &wallet,
            seed.saturating_add(1),
            1_700_000_000u64.saturating_add(seed),
        ) {
            Ok(outcome) => outcome,
            Err(err) => panic!("insert failed for seed {seed}: {err:?}"),
        };

        assert_eq!(inserted, RegisterOutcome::Inserted);
    }

    for seed in 0u64..32u64 {
        let wallet = wallet_u64(seed);
        let renewed = match ValidatorLifecycle::apply_register_or_renew(
            &mut map,
            &wallet,
            seed.saturating_add(100),
            1_700_000_500u64.saturating_add(seed),
        ) {
            Ok(outcome) => outcome,
            Err(err) => panic!("renew failed for seed {seed}: {err:?}"),
        };

        assert_eq!(renewed, RegisterOutcome::Renewed);
    }

    assert_eq!(map.len(), 32);

    for (wallet, meta) in &map {
        assert!(meta.validate_invariants(wallet).is_ok());
        assert!(meta.last_renew_height >= meta.join_height);
        assert!(meta.last_renew_timestamp >= meta.join_timestamp);
    }
}

#[test]
fn blockchainconsensus_121_liveness_clear_buffered_unknown_parent_proofs_removes_one_and_is_idempotent()
 {
    let mut ctx =
        must_ctx("liveness_clear_buffered_unknown_parent_proofs_removes_one_and_is_idempotent");
    let parent = nonzero_hash(121);
    let proof = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 121, parent);

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        1
    );

    let removed = ctx
        .consensus
        .clear_buffered_unknown_parent_puzzle_proofs_for_liveness("test clear one orphan proof");

    assert_eq!(removed, 1);
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        0
    );

    let removed_again = ctx
        .consensus
        .clear_buffered_unknown_parent_puzzle_proofs_for_liveness("test clear empty orphan buffer");

    assert_eq!(removed_again, 0);
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_122_liveness_reset_runtime_proposal_safety_state_clears_orphan_buffer() {
    let mut ctx = must_ctx("liveness_reset_runtime_proposal_safety_state_clears_orphan_buffer");

    let parent_a = nonzero_hash(122);
    let parent_b = nonzero_hash(123);

    let proof_a = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 122, parent_a);
    let proof_b = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 123, parent_b);

    assert!(ctx.consensus.on_puzzle_proof(&proof_a));
    assert!(ctx.consensus.on_puzzle_proof(&proof_b));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 2);

    ctx.consensus
        .set_runtime_rejoin_catchup_gate(true, Some("test catchup".to_owned()));
    ctx.consensus.set_runtime_branch_hydration_active(true);

    ctx.consensus
        .reset_runtime_proposal_safety_state(77, nonzero_hash(77));

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
    assert!(!ctx.consensus.runtime_rejoin_catchup_gate_active());
    assert!(!ctx.consensus.runtime_branch_hydration_active());
    assert_eq!(ctx.consensus.validator_state_rebuilt_at_tip(), Some(77));
}

#[test]
fn blockchainconsensus_123_liveness_clear_orphan_buffer_does_not_touch_registry_or_rebuild_marker()
{
    let mut ctx =
        must_ctx("liveness_clear_orphan_buffer_does_not_touch_registry_or_rebuild_marker");
    let parent = nonzero_hash(124);
    let proof = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 124, parent);

    ctx.consensus
        .set_registry(must_registry(&[ctx.local_wallet.clone()]));
    ctx.consensus.note_validator_state_rebuilt_to_tip(44);

    assert!(
        ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&ctx.local_wallet)
    );
    assert_eq!(ctx.consensus.validator_state_rebuilt_at_tip(), Some(44));

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);

    let removed = ctx
        .consensus
        .clear_buffered_unknown_parent_puzzle_proofs_for_liveness(
            "test clear must not mutate unrelated state",
        );

    assert_eq!(removed, 1);
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
    assert!(
        ctx.consensus
            .committee_eligibility()
            .is_wallet_live(&ctx.local_wallet)
    );
    assert_eq!(ctx.consensus.validator_state_rebuilt_at_tip(), Some(44));
}

#[test]
fn blockchainconsensus_124_liveness_duplicate_orphan_proof_counts_once_then_clears_once() {
    let mut ctx = must_ctx("liveness_duplicate_orphan_proof_counts_once_then_clears_once");
    let parent = nonzero_hash(125);
    let proof = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 125, parent);

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    assert!(ctx.consensus.on_puzzle_proof(&proof));
    assert!(ctx.consensus.on_puzzle_proof(&proof));

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        1
    );

    let removed = ctx
        .consensus
        .clear_buffered_unknown_parent_puzzle_proofs_for_liveness("test clear duplicate orphan");

    assert_eq!(removed, 1);
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_125_liveness_invalid_gossip_does_not_wipe_existing_orphan_buffer() {
    let mut ctx = must_ctx("liveness_invalid_gossip_does_not_wipe_existing_orphan_buffer");
    let good_parent = nonzero_hash(126);
    let bad_parent = nonzero_hash(127);

    let good = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 126, good_parent);
    assert!(ctx.consensus.on_puzzle_proof(&good));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);

    let mut bad = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 127, bad_parent);
    bad.output = bad.output.saturating_add(1);

    assert!(!ctx.consensus.on_puzzle_proof(&bad));

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(good_parent),
        1
    );
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(bad_parent),
        0
    );
}

#[test]
fn blockchainconsensus_126_liveness_gc_below_prunes_lower_orphan_but_keeps_higher_orphan() {
    let mut ctx = must_ctx("liveness_gc_below_prunes_lower_orphan_but_keeps_higher_orphan");

    let low_parent = nonzero_hash(128);
    let high_parent = nonzero_hash(129);

    let low = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 128, low_parent);
    let high = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 130, high_parent);

    assert!(ctx.consensus.on_puzzle_proof(&low));
    assert!(ctx.consensus.on_puzzle_proof(&high));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 2);

    ctx.consensus.gc_puzzle_pool_below(129);

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(low_parent),
        0
    );
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(high_parent),
        1
    );
}

#[test]
fn blockchainconsensus_127_liveness_gc_below_large_height_clears_all_orphan_buffers() {
    let mut ctx = must_ctx("liveness_gc_below_large_height_clears_all_orphan_buffers");

    for i in 0u8..5u8 {
        let height = 140u64.saturating_add(u64::from(i));
        let parent = nonzero_hash(140u8.saturating_add(i));
        let proof = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, height, parent);

        assert!(ctx.consensus.on_puzzle_proof(&proof));
    }

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 5);

    ctx.consensus.gc_puzzle_pool_below(10_000);

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
}

#[test]
fn blockchainconsensus_128_liveness_per_parent_orphan_buffer_is_capped() {
    let mut ctx = must_ctx("liveness_per_parent_orphan_buffer_is_capped");
    let parent = nonzero_hash(150);

    for i in 0u64..40u64 {
        let wallet = wallet_u64(1_000u64.saturating_add(i));
        let height = 150u64.saturating_add(i);
        let proof = valid_gossip_proof_for_extra_tests(&wallet, height, parent);

        assert!(ctx.consensus.on_puzzle_proof(&proof));
        assert!(
            ctx.consensus
                .pending_buffered_puzzle_proof_count_for_parent(parent)
                <= 32,
            "per-parent orphan buffer exceeded liveness cap"
        );
    }

    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        32
    );
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 32);
}

#[test]
fn blockchainconsensus_129_liveness_clear_after_per_parent_cap_removes_only_retained_orphans() {
    let mut ctx = must_ctx("liveness_clear_after_per_parent_cap_removes_only_retained_orphans");
    let parent = nonzero_hash(151);

    for i in 0u64..40u64 {
        let wallet = wallet_u64(2_000u64.saturating_add(i));
        let height = 200u64.saturating_add(i);
        let proof = valid_gossip_proof_for_extra_tests(&wallet, height, parent);

        assert!(ctx.consensus.on_puzzle_proof(&proof));
    }

    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        32
    );
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 32);

    let removed = ctx
        .consensus
        .clear_buffered_unknown_parent_puzzle_proofs_for_liveness(
            "test clear capped orphan buffer",
        );

    assert_eq!(removed, 32);
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 0);
    assert_eq!(
        ctx.consensus
            .pending_buffered_puzzle_proof_count_for_parent(parent),
        0
    );
}

#[test]
fn blockchainconsensus_130_liveness_buffered_orphan_error_message_is_not_used_as_build_blocker() {
    let mut ctx = must_ctx("liveness_buffered_orphan_error_message_is_not_used_as_build_blocker");

    let orphan_parent = nonzero_hash(152);
    let build_parent = nonzero_hash(153);
    let proof = valid_gossip_proof_for_extra_tests(&ctx.local_wallet, 152, orphan_parent);

    assert!(ctx.consensus.on_puzzle_proof(&proof));
    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);

    let result = ctx.consensus.assert_can_build_block(1, build_parent, false);

    match result {
        Ok(()) => panic!("expected unknown local parent to reject build"),
        Err(err) => {
            let text = format!("{err:?}");
            let lower = text.to_ascii_lowercase();

            assert!(
                lower.contains("parent hash is not known"),
                "expected real local-parent safety error, got: {text}"
            );
            assert!(
                !lower.contains("buffered unknown-parent puzzle proof"),
                "orphan buffer reintroduced as build blocker: {text}"
            );
        }
    }

    assert_eq!(ctx.consensus.pending_buffered_puzzle_proof_total(), 1);
}
