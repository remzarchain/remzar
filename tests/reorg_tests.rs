#![cfg(test)]

use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::network::p2p_006_reqresp::Hash;
use remzar::reorganization::reorg_001_block_index::ReorgBlockIndex;
use remzar::reorganization::reorg_002_chain_view::ReorgChainView;
use remzar::reorganization::reorg_004_batch_index::ReorgBatchIndex;
use remzar::reorganization::reorg_005_fork_choice::ForkAction;
use remzar::reorganization::reorg_006_manager::ReorgManager;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::storage::rocksdb_006_manager_ext::{ForkBlockMeta, ForkBlockStatus};
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

type TestResult<T = ()> = Result<T, String>;

#[derive(Debug)]
struct SeededNode {
    _temp_root: PathBuf,
    db: Arc<RockDBManager>,
    chain: AccountModelTree,
}

#[derive(Debug, Clone)]
struct Branch {
    blocks: Vec<Block>,
    batches: Vec<Vec<u8>>,
}

fn fmt_err<E: std::fmt::Debug>(e: E) -> String {
    format!("{:?}", e)
}

fn now_secs(offset: u64) -> u64 {
    1_750_000_000u64.saturating_add(offset)
}

fn unique_temp_root(prefix: &str) -> PathBuf {
    let nanos = u128::try_from(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)).unwrap_or(0);

    std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), nanos))
}

fn make_test_node_opts(temp_root: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: temp_root.join("identity.key").to_string_lossy().to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "info".to_string(),
        data_dir: temp_root.to_string_lossy().to_string(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_string(),
        founder: false,
    }
}

fn make_batch_bytes(index: u64, salt: u64) -> TestResult<Vec<u8>> {
    let batch = TransactionBatch {
        index,
        timestamp: now_secs(10_000 + salt),
        transactions: vec![],
        guardian_signature: None,
    };

    batch.serialize().map_err(fmt_err)
}

fn make_block(index: u64, prev_hash: Hash, merkle_byte: u8) -> TestResult<Block> {
    let merkle_fill = if merkle_byte == 0 { 1 } else { merkle_byte };

    let guardian_signature = if index == 0 {
        [0u8; ml_dsa_65::SIG_LEN]
    } else {
        [merkle_fill; ml_dsa_65::SIG_LEN]
    };

    let metadata = BlockMetadata::new(
        index,
        now_secs(index),
        prev_hash,
        [merkle_fill; 64],
        guardian_signature,
        None,
        GlobalConfiguration::MAX_BLOCK_SIZE,
    );

    Block::new(
        metadata,
        Some(format!("tx_batch_{:010}", index)),
        GlobalConfiguration::GENESIS_VALIDATOR.to_string(),
        0,
    )
    .map_err(fmt_err)
}

fn make_node(prefix: &str) -> TestResult<SeededNode> {
    let temp_root = unique_temp_root(prefix);
    fs::create_dir_all(&temp_root).map_err(fmt_err)?;

    let db_dir = temp_root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let opts = make_test_node_opts(&temp_root);

    let db = Arc::new(
        RockDBManager::new_blockchain(
            &opts,
            db_dir
                .to_str()
                .ok_or_else(|| "temp blockchain path is not valid UTF-8".to_string())?,
        )
        .map_err(fmt_err)?,
    );

    let chain = AccountModelTree::with_manager((*db).clone());

    Ok(SeededNode {
        _temp_root: temp_root,
        db,
        chain,
    })
}

fn reopen_node_from(root: &Path) -> TestResult<SeededNode> {
    let db_dir = root.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let opts = make_test_node_opts(root);
    let db = Arc::new(
        RockDBManager::new_blockchain(
            &opts,
            db_dir
                .to_str()
                .ok_or_else(|| "temp blockchain path is not valid UTF-8".to_string())?,
        )
        .map_err(fmt_err)?,
    );
    let chain = AccountModelTree::with_manager((*db).clone());
    Ok(SeededNode {
        _temp_root: root.to_path_buf(),
        db,
        chain,
    })
}

#[allow(clippy::too_many_arguments)]
fn ingest_block(
    db: &Arc<RockDBManager>,
    block_index: &ReorgBlockIndex,
    chain_view: &ReorgChainView,
    batch_index: &ReorgBatchIndex,
    block: &Block,
    batch_bytes: &[u8],
    status: ForkBlockStatus,
    score: u128,
) -> TestResult {
    let meta = ForkBlockMeta {
        parent_hash: block.metadata.previous_hash,
        height: block.metadata.index,
        cumulative_score: score,
        status,
        received_at_unix_secs: now_secs(20_000 + block.metadata.index),
    };

    block_index
        .ingest_validated_block(block, meta, Some(batch_bytes))
        .map_err(fmt_err)?;

    match status {
        ForkBlockStatus::Canonical => {
            let block_bytes = block.serialize_for_storage().map_err(fmt_err)?;
            db.store_latest_block(&block_bytes, block.metadata.index)
                .map_err(fmt_err)?;
            batch_index
                .set_canonical_batch_at_height(block.metadata.index, batch_bytes)
                .map_err(fmt_err)?;
            chain_view
                .set_hash_at_height(block.metadata.index, &block.block_hash)
                .map_err(fmt_err)?;
            block_index
                .mark_canonical(&block.block_hash)
                .map_err(fmt_err)?;
        }
        ForkBlockStatus::SideBranch => {
            block_index
                .mark_side_branch(&block.block_hash)
                .map_err(fmt_err)?;
        }
        _ => {}
    }

    Ok(())
}

fn make_branch(base: &Block, start_height: u64, len: u64, salt: u8) -> TestResult<Branch> {
    let mut prev = base.block_hash;
    let mut blocks = Vec::new();
    let mut batches = Vec::new();

    for i in 0..len {
        let h = start_height + i;
        let block = make_block(h, prev, salt.wrapping_add(i as u8).max(1))?;
        let batch = make_batch_bytes(h, (salt as u64) * 100 + i)?;
        prev = block.block_hash;
        blocks.push(block);
        batches.push(batch);
    }

    Ok(Branch { blocks, batches })
}

fn seed_canonical_prefix(node: &Arc<RockDBManager>, prefix_len: u64) -> TestResult<Vec<Block>> {
    let block_index = ReorgBlockIndex::new(Arc::clone(node));
    let chain_view = ReorgChainView::new(Arc::clone(node));
    let batch_index = ReorgBatchIndex::new(Arc::clone(node));

    let genesis = make_block(0, [0u8; 64], 0x11)?;
    let genesis_batch = make_batch_bytes(0, 0)?;
    ingest_block(
        node,
        &block_index,
        &chain_view,
        &batch_index,
        &genesis,
        &genesis_batch,
        ForkBlockStatus::Canonical,
        0,
    )?;

    let mut canonical = vec![genesis.clone()];
    let mut prev = genesis;
    for h in 1..=prefix_len {
        let b = make_block(h, prev.block_hash, 0x20u8.wrapping_add(h as u8))?;
        let batch = make_batch_bytes(h, h)?;
        ingest_block(
            node,
            &block_index,
            &chain_view,
            &batch_index,
            &b,
            &batch,
            ForkBlockStatus::Canonical,
            h as u128,
        )?;
        canonical.push(b.clone());
        prev = b;
    }

    chain_view
        .set_tip(&prev.block_hash, prev.metadata.index)
        .map_err(fmt_err)?;

    Ok(canonical)
}

fn ingest_side_branch(node: &Arc<RockDBManager>, branch: &Branch, base_score: u128) -> TestResult {
    let block_index = ReorgBlockIndex::new(Arc::clone(node));
    for (i, block) in branch.blocks.iter().enumerate() {
        ingest_block(
            node,
            &block_index,
            &ReorgChainView::new(Arc::clone(node)),
            &ReorgBatchIndex::new(Arc::clone(node)),
            block,
            &branch.batches[i],
            ForkBlockStatus::SideBranch,
            base_score + (i as u128) + 1,
        )?;
    }
    Ok(())
}

fn assert_tip(node: &Arc<RockDBManager>, expected_height: u64, expected_hash: Hash) -> TestResult {
    let tip = ReorgChainView::new(Arc::clone(node))
        .get_tip_with_legacy_fallback()
        .map_err(fmt_err)?
        .ok_or_else(|| "missing canonical tip".to_string())?;
    assert_eq!(tip.tip_height, expected_height);
    assert_eq!(tip.tip_hash, expected_hash);
    Ok(())
}

fn assert_projection_matches_branch(
    node: &Arc<RockDBManager>,
    start_height: u64,
    branch: &Branch,
) -> TestResult {
    let chain_view = ReorgChainView::new(Arc::clone(node));
    for (i, block) in branch.blocks.iter().enumerate() {
        let h = start_height + i as u64;
        let hash = chain_view
            .get_hash_at_height(h)
            .map_err(fmt_err)?
            .ok_or_else(|| format!("missing canonical hash at height {h}"))?;
        assert_eq!(hash, block.block_hash, "height {h} mismatch");
    }
    Ok(())
}

fn run_reorg(node: &mut SeededNode, tip_block: &Block) -> TestResult<ForkAction> {
    ReorgManager::mainnet_default(Arc::clone(&node.db))
        .handle_new_block(tip_block, &mut node.chain, None)
        .map_err(fmt_err)
}

#[test]
fn equal_length_competing_branch_does_not_reorg() -> TestResult {
    let mut node = make_node("remzar_equal_length")?;
    let canonical = seed_canonical_prefix(&node.db, 2)?;
    let base = &canonical[1];
    let side = make_branch(base, 2, 1, 0x70)?;
    ingest_side_branch(&node.db, &side, 1)?;

    match run_reorg(&mut node, &side.blocks[0])? {
        ForkAction::Stay => {}
        other => {
            return Err(format!(
                "expected STAY on equal-length branch, got {other:?}"
            ));
        }
    }

    assert_tip(&node.db, 2, canonical[2].block_hash)
}

#[test]
fn deeper_reorg_replaces_multiple_heights() -> TestResult {
    let mut node = make_node("remzar_deeper_reorg")?;
    let canonical = seed_canonical_prefix(&node.db, 5)?;
    let fork_base = &canonical[1];
    let side = make_branch(fork_base, 2, 5, 0x80)?;
    ingest_side_branch(&node.db, &side, 1)?;

    let plan = match run_reorg(&mut node, side.blocks.last().unwrap())? {
        ForkAction::Reorg(plan) => plan,
        other => return Err(format!("expected REORG for deeper branch, got {other:?}")),
    };

    let detach_heights: Vec<u64> = plan.detach.iter().map(|s| s.height).collect();
    let attach_heights: Vec<u64> = plan.attach.iter().map(|s| s.height).collect();
    assert_eq!(plan.common_ancestor_height, 1);
    assert_eq!(detach_heights, vec![5, 4, 3, 2]);
    assert_eq!(attach_heights, vec![2, 3, 4, 5, 6]);

    let mut detach_sorted = detach_heights.clone();
    detach_sorted.sort_unstable();
    assert_eq!(detach_sorted, vec![2, 3, 4, 5]);

    assert_tip(&node.db, 6, side.blocks[4].block_hash)?;
    assert_projection_matches_branch(&node.db, 2, &side)
}

#[test]
fn delayed_delivery_only_reorgs_when_winning_tip_arrives() -> TestResult {
    let mut node = make_node("remzar_delayed_delivery")?;
    let canonical = seed_canonical_prefix(&node.db, 3)?;
    let fork_base = &canonical[1];
    let side = make_branch(fork_base, 2, 3, 0x90)?;

    ingest_side_branch(
        &node.db,
        &Branch {
            blocks: vec![side.blocks[0].clone()],
            batches: vec![side.batches[0].clone()],
        },
        1,
    )?;
    ingest_side_branch(
        &node.db,
        &Branch {
            blocks: vec![side.blocks[1].clone()],
            batches: vec![side.batches[1].clone()],
        },
        2,
    )?;

    match run_reorg(&mut node, &side.blocks[1])? {
        ForkAction::Stay => {}
        other => {
            return Err(format!(
                "expected STAY before branch is longer, got {other:?}"
            ));
        }
    }

    ingest_side_branch(
        &node.db,
        &Branch {
            blocks: vec![side.blocks[2].clone()],
            batches: vec![side.batches[2].clone()],
        },
        3,
    )?;
    match run_reorg(&mut node, &side.blocks[2])? {
        ForkAction::Reorg(_) => {}
        other => {
            return Err(format!(
                "expected REORG after winning tip arrives, got {other:?}"
            ));
        }
    }

    assert_tip(&node.db, 4, side.blocks[2].block_hash)
}

#[test]
fn five_independent_nodes_converge_on_same_canonical_tip() -> TestResult {
    let mut nodes: Vec<SeededNode> = (0..5)
        .map(|i| make_node(&format!("remzar_converge_node_{i}")))
        .collect::<Result<Vec<_>, _>>()?;

    let canonical = seed_canonical_prefix(&nodes[0].db, 3)?;
    let fork_base = &canonical[1];
    let winning = make_branch(fork_base, 2, 3, 0xA0)?;

    for node in nodes.iter_mut().skip(1) {
        seed_canonical_prefix(&node.db, 3)?;
    }
    for node in nodes.iter() {
        ingest_side_branch(&node.db, &winning, 1)?;
    }
    for node in nodes.iter_mut() {
        match run_reorg(node, winning.blocks.last().unwrap())? {
            ForkAction::Reorg(_) => {}
            other => {
                return Err(format!(
                    "expected REORG on node convergence test, got {other:?}"
                ));
            }
        }
    }

    let expected_hash = winning.blocks.last().unwrap().block_hash;
    for node in nodes.iter() {
        assert_tip(&node.db, 4, expected_hash)?;
    }
    Ok(())
}

#[test]
fn duplicate_delivery_is_idempotent_after_first_reorg() -> TestResult {
    let mut node = make_node("remzar_idempotent")?;
    let canonical = seed_canonical_prefix(&node.db, 3)?;
    let winning = make_branch(&canonical[1], 2, 3, 0xB0)?;
    ingest_side_branch(&node.db, &winning, 1)?;

    match run_reorg(&mut node, winning.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("first delivery should reorg, got {other:?}")),
    }
    match run_reorg(&mut node, winning.blocks.last().unwrap())? {
        ForkAction::Stay => {}
        ForkAction::Reorg(_) => return Err("duplicate winning tip should not reorg twice".into()),
        ForkAction::NeedMoreData {
            missing_hash,
            context,
        } => {
            return Err(format!(
                "duplicate delivery unexpectedly needed data: {} {}",
                hex::encode(missing_hash),
                context
            ));
        }
    }

    assert_tip(&node.db, 4, winning.blocks.last().unwrap().block_hash)
}

#[test]
fn reorg_can_switch_twice_a_to_b_to_c() -> TestResult {
    let mut node = make_node("remzar_a_to_b_to_c")?;
    let canonical = seed_canonical_prefix(&node.db, 3)?;
    let base = &canonical[1];
    let branch_b = make_branch(base, 2, 3, 0xB1)?;
    let branch_c = make_branch(base, 2, 4, 0xC1)?;

    ingest_side_branch(&node.db, &branch_b, 1)?;
    match run_reorg(&mut node, branch_b.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("expected first reorg to B, got {other:?}")),
    }
    assert_tip(&node.db, 4, branch_b.blocks.last().unwrap().block_hash)?;

    ingest_side_branch(&node.db, &branch_c, 1)?;
    match run_reorg(&mut node, branch_c.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("expected second reorg to C, got {other:?}")),
    }
    assert_tip(&node.db, 5, branch_c.blocks.last().unwrap().block_hash)
}

#[test]
fn out_of_order_branch_delivery_eventually_converges() -> TestResult {
    let mut node = make_node("remzar_out_of_order")?;
    let canonical = seed_canonical_prefix(&node.db, 3)?;
    let side = make_branch(&canonical[1], 2, 4, 0xD0)?;

    // deliver 5, 3, 4, 2 equivalent via unordered ingest into side-branch index
    for idx in [3usize, 1usize, 2usize, 0usize] {
        let single = Branch {
            blocks: vec![side.blocks[idx].clone()],
            batches: vec![side.batches[idx].clone()],
        };
        ingest_side_branch(&node.db, &single, 1 + idx as u128)?;
    }

    match run_reorg(&mut node, side.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        ForkAction::NeedMoreData { .. } => {
            return Err("expected converged data after unordered ingest".into());
        }
        other => {
            return Err(format!(
                "expected REORG after unordered delivery, got {other:?}"
            ));
        }
    }

    assert_tip(&node.db, 5, side.blocks.last().unwrap().block_hash)
}

#[test]
fn two_competing_side_branches_choose_best_one() -> TestResult {
    let mut node = make_node("remzar_two_competing_sides")?;
    let canonical = seed_canonical_prefix(&node.db, 3)?;
    let base = &canonical[1];
    let branch_b = make_branch(base, 2, 3, 0xE1)?;
    let branch_c = make_branch(base, 2, 4, 0xE2)?;

    ingest_side_branch(&node.db, &branch_b, 1)?;
    ingest_side_branch(&node.db, &branch_c, 1)?;

    match run_reorg(&mut node, branch_b.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => {
            return Err(format!(
                "branch B should already beat canonical, got {other:?}"
            ));
        }
    }
    assert_tip(&node.db, 4, branch_b.blocks.last().unwrap().block_hash)?;

    match run_reorg(&mut node, branch_c.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("branch C should beat branch B, got {other:?}")),
    }
    assert_tip(&node.db, 5, branch_c.blocks.last().unwrap().block_hash)
}

#[test]
fn reorg_depth_boundaries_1_2_5_and_8() -> TestResult {
    for depth in [1u64, 2, 5, 8] {
        let mut node = make_node(&format!("remzar_depth_{depth}"))?;
        let canonical = seed_canonical_prefix(&node.db, depth + 1)?;
        let side = make_branch(
            &canonical[1],
            2,
            depth + 1,
            0x30u8.wrapping_add(depth as u8),
        )?;
        ingest_side_branch(&node.db, &side, 1)?;

        match run_reorg(&mut node, side.blocks.last().unwrap())? {
            ForkAction::Reorg(_) => {}
            other => return Err(format!("expected REORG at depth {depth}, got {other:?}")),
        }
        assert_tip(&node.db, depth + 2, side.blocks.last().unwrap().block_hash)?;
    }
    Ok(())
}

#[test]
fn genesis_near_reorg_works() -> TestResult {
    let mut node = make_node("remzar_genesis_near")?;
    let canonical = seed_canonical_prefix(&node.db, 1)?; // 0 -> 1
    let side = make_branch(&canonical[0], 1, 2, 0xF0)?; // fork directly off genesis: 1 -> 2
    ingest_side_branch(&node.db, &side, 0)?;

    match run_reorg(&mut node, side.blocks.last().unwrap())? {
        ForkAction::Reorg(plan) => assert_eq!(plan.common_ancestor_height, 0),
        other => return Err(format!("expected genesis-near REORG, got {other:?}")),
    }
    assert_tip(&node.db, 2, side.blocks.last().unwrap().block_hash)
}

#[test]
fn replayed_state_matches_post_reorg_tip() -> TestResult {
    let mut node = make_node("remzar_replay_equivalence")?;
    let canonical = seed_canonical_prefix(&node.db, 4)?;
    let side = make_branch(&canonical[1], 2, 4, 0x44)?;
    ingest_side_branch(&node.db, &side, 1)?;

    match run_reorg(&mut node, side.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("expected REORG, got {other:?}")),
    }

    let after = ReorgChainView::new(Arc::clone(&node.db))
        .get_tip_with_legacy_fallback()
        .map_err(fmt_err)?
        .ok_or_else(|| "missing canonical tip after reorg".to_string())?;

    node.chain
        .reload_from_db_to_height(after.tip_height)
        .map_err(fmt_err)?;
    let replay_tip_idx = node.chain.latest_block_height();
    let replay_tip_block = node
        .chain
        .get_block_by_index(replay_tip_idx)
        .map_err(fmt_err)?;
    assert_eq!(replay_tip_idx as u64, after.tip_height);
    assert_eq!(replay_tip_block.block_hash, after.tip_hash);
    Ok(())
}

#[test]
fn projection_consistency_after_reorg() -> TestResult {
    let mut node = make_node("remzar_projection_consistency")?;
    let canonical = seed_canonical_prefix(&node.db, 5)?;
    let side = make_branch(&canonical[1], 2, 5, 0x55)?;
    ingest_side_branch(&node.db, &side, 1)?;
    match run_reorg(&mut node, side.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("expected REORG, got {other:?}")),
    }

    let chain_view = ReorgChainView::new(Arc::clone(&node.db));
    let tip = chain_view
        .get_tip_with_legacy_fallback()
        .map_err(fmt_err)?
        .ok_or_else(|| "missing tip".to_string())?;
    assert_eq!(tip.tip_height, 6);
    assert_eq!(tip.tip_hash, side.blocks.last().unwrap().block_hash);

    for (i, block) in side.blocks.iter().enumerate() {
        let h = 2 + i as u64;
        let hash = chain_view
            .get_hash_at_height(h)
            .map_err(fmt_err)?
            .ok_or_else(|| format!("missing hash at {h}"))?;
        let stored_block = node
            .db
            .get_block_by_index(h)
            .map_err(fmt_err)?
            .ok_or_else(|| format!("missing block projection at {h}"))?;
        let stored_batch = node
            .db
            .get_batch_bytes_by_index(h)
            .map_err(fmt_err)?
            .ok_or_else(|| format!("missing batch projection at {h}"))?;
        assert_eq!(hash, block.block_hash);
        assert_eq!(stored_block.block_hash, block.block_hash);
        assert_eq!(stored_batch, side.batches[i]);
    }
    Ok(())
}

#[test]
fn persistence_across_restart_preserves_reorg_result() -> TestResult {
    let mut node = make_node("remzar_restart_persistence")?;
    let root = node._temp_root.clone();
    let canonical = seed_canonical_prefix(&node.db, 3)?;
    let side = make_branch(&canonical[1], 2, 3, 0x66)?;
    ingest_side_branch(&node.db, &side, 1)?;
    match run_reorg(&mut node, side.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("expected REORG before restart, got {other:?}")),
    }
    let expected = side.blocks.last().unwrap().block_hash;
    drop(node);

    let reopened = reopen_node_from(&root)?;
    assert_tip(&reopened.db, 4, expected)
}

#[test]
fn no_op_on_current_canonical_tip() -> TestResult {
    let mut node = make_node("remzar_noop_current_tip")?;
    let canonical = seed_canonical_prefix(&node.db, 3)?;
    match run_reorg(&mut node, &canonical[3])? {
        ForkAction::Stay => {}
        other => {
            return Err(format!(
                "current canonical tip should be a no-op, got {other:?}"
            ));
        }
    }
    assert_tip(&node.db, 3, canonical[3].block_hash)
}

#[test]
fn shorter_side_branch_never_beats_canonical() -> TestResult {
    let mut node = make_node("remzar_shorter_side")?;
    let canonical = seed_canonical_prefix(&node.db, 5)?;
    let side = make_branch(&canonical[2], 3, 2, 0x77)?; // ends at 4, canonical at 5
    ingest_side_branch(&node.db, &side, 2)?;
    match run_reorg(&mut node, side.blocks.last().unwrap())? {
        ForkAction::Stay => {}
        other => {
            return Err(format!(
                "shorter side branch should not reorg, got {other:?}"
            ));
        }
    }
    assert_tip(&node.db, 5, canonical[5].block_hash)
}

#[test]
fn branch_statuses_remain_usable_after_second_switch() -> TestResult {
    let mut node = make_node("remzar_status_after_switch")?;
    let canonical = seed_canonical_prefix(&node.db, 3)?;
    let base = &canonical[1];
    let branch_b = make_branch(base, 2, 3, 0x81)?;
    let branch_c = make_branch(base, 2, 4, 0x82)?;
    ingest_side_branch(&node.db, &branch_b, 1)?;
    ingest_side_branch(&node.db, &branch_c, 1)?;

    match run_reorg(&mut node, branch_b.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("expected reorg to B, got {other:?}")),
    }
    match run_reorg(&mut node, branch_c.blocks.last().unwrap())? {
        ForkAction::Reorg(_) => {}
        other => return Err(format!("expected reorg to C after B, got {other:?}")),
    }
    assert_tip(&node.db, 5, branch_c.blocks.last().unwrap().block_hash)
}

#[test]
fn convergence_still_holds_when_nodes_receive_winner_at_different_times() -> TestResult {
    let mut nodes: Vec<SeededNode> = (0..5)
        .map(|i| make_node(&format!("remzar_stagger_converge_{i}")))
        .collect::<Result<Vec<_>, _>>()?;
    let canonical = seed_canonical_prefix(&nodes[0].db, 3)?;
    for node in nodes.iter_mut().skip(1) {
        seed_canonical_prefix(&node.db, 3)?;
    }
    let winning = make_branch(&canonical[1], 2, 3, 0x91)?;

    for (i, node) in nodes.iter_mut().enumerate() {
        for j in 0..=i.min(2) {
            let single = Branch {
                blocks: vec![winning.blocks[j].clone()],
                batches: vec![winning.batches[j].clone()],
            };
            ingest_side_branch(&node.db, &single, 1 + j as u128)?;
        }
    }
    for node in nodes.iter_mut() {
        ingest_side_branch(&node.db, &winning, 1)?;
        match run_reorg(node, winning.blocks.last().unwrap())? {
            ForkAction::Reorg(_) => {}
            other => {
                return Err(format!(
                    "staggered convergence expected REORG, got {other:?}"
                ));
            }
        }
    }

    let expected = winning.blocks.last().unwrap().block_hash;
    for node in nodes.iter() {
        assert_tip(&node.db, 4, expected)?;
    }
    Ok(())
}
