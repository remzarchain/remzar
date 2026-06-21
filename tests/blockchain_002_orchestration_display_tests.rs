// tests/blockchain_002_orchestration_display_tests.rs

use fips204::ml_dsa_65;
use remzar::blockchain::block_001_metadata::BlockMetadata;
use remzar::blockchain::block_002_blocks::Block;
use remzar::blockchain::blockchain_002_orchestration_display::OrchestrationDisplay;
use remzar::blockchain::halving_schedule::RewardHalving;
use remzar::blockchain::transaction_002_tx_register::RegisterNodeTx;
use remzar::blockchain::transaction_004_tx_kind::TxKind;
use remzar::blockchain::transaction_005_tx_account_tree::AccountModelTree;
use remzar::blockchain::transaction_005_tx_batch::TransactionBatch;
use remzar::commandline::s_04_view_blockchain_console::ConsoleBus;
use remzar::runtime::p2p_006_sync_runtime::NodeOpts;
use remzar::storage::rocksdb_005_manager::RockDBManager;
use remzar::utility::alpha_001_global_configuration::GlobalConfiguration;
use remzar::utility::helper;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast::error::TryRecvError;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct DisplayCtx {
    db: Arc<RockDBManager>,

    display: OrchestrationDisplay,
    bus: ConsoleBus,
}

fn extra_display_make_batch_bytes(height: u64, tx_count: usize) -> Vec<u8> {
    let txs = (0usize..tx_count)
        .map(|i| make_register_kind(u64::try_from(i).unwrap_or(0).saturating_add(height * 1_000)))
        .collect::<Vec<_>>();

    let batch = match TransactionBatch::new(height, 1_700_000_000u64.saturating_add(height), txs) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    match batch.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TransactionBatch::serialize failed: {err:?}"),
    }
}

fn extra_display_store_batch_under_key(ctx: &DisplayCtx, key: &str, height: u64, tx_count: usize) {
    let bytes = extra_display_make_batch_bytes(height, tx_count);

    match ctx.db.write(
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        key.as_bytes(),
        &bytes,
    ) {
        Ok(()) => {}
        Err(err) => panic!("write custom batch failed: {err:?}"),
    }
}

fn extra_display_field(line: &str, label: &str) -> String {
    for part in line.split('|') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(label) {
            return value.trim().to_owned();
        }
    }

    panic!("field '{label}' missing in line: {line}");
}

fn extra_display_store_custom_batch_key_block(
    ctx: &DisplayCtx,
    height: u64,
    batch_key: Option<String>,
) -> Block {
    let meta = BlockMetadata::new(
        height,
        1_700_000_000u64.saturating_add(height),
        nonzero_hash(41),
        nonzero_hash(42),
        nonzero_sig(43),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    let block = match Block::new(meta, batch_key, wallet_u64(height.saturating_add(2_000)), 0) {
        Ok(block) => block,
        Err(err) => panic!("Block::new custom batch key failed: {err:?}"),
    };

    store_block(ctx, &block);
    block
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
        "remzar_blockchain_002_orchestration_display_tests_{name}_{}_{}",
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

fn new_db(name: &str) -> Result<Arc<RockDBManager>, String> {
    let base_dir = unique_test_dir(name);
    let blockchain_dir = base_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);

    let mut opts = NodeOpts::default();
    opts.data_dir = path_to_string(&base_dir)?;
    opts.identity_file = path_to_string(&base_dir.join("identity.key"))?;
    opts.wallet_address = wallet_u64(1);

    let blockchain_dir_str = path_to_string(&blockchain_dir)?;
    let db_inner =
        RockDBManager::new_blockchain(&opts, &blockchain_dir_str).map_err(err_to_string)?;

    db_inner.set_latest_block_index(0).map_err(err_to_string)?;
    db_inner.set_tip_height(0).map_err(err_to_string)?;

    Ok(Arc::new(db_inner))
}

fn new_ctx(name: &str) -> DisplayCtx {
    let db = match new_db(name) {
        Ok(db) => db,
        Err(err) => panic!("failed to create db: {err}"),
    };

    let bus = ConsoleBus::new();
    let display = OrchestrationDisplay::new(Arc::clone(&db), bus.clone());

    DisplayCtx { db, display, bus }
}

fn account_tree(ctx: &DisplayCtx) -> AccountModelTree {
    let mut tree = AccountModelTree::with_manager((*ctx.db).clone());
    tree.reload_from_db();
    tree
}

fn display_with_log_sequence(mut ctx: DisplayCtx, enabled: bool) -> DisplayCtx {
    ctx.display.log_sequence = enabled;
    ctx
}

fn make_block(height: u64, prev_hash: [u8; 64]) -> Block {
    let signature = if height == 0 {
        [0u8; ml_dsa_65::SIG_LEN]
    } else {
        nonzero_sig(17)
    };

    let previous_hash = if height == 0 { [0u8; 64] } else { prev_hash };

    let meta = BlockMetadata::new(
        height,
        1_700_000_000u64.saturating_add(height),
        previous_hash,
        nonzero_hash(33),
        signature,
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    let batch_key = if height == 0 {
        None
    } else {
        Some(format!("tx_batch_{height:010}"))
    };

    match Block::new(meta, batch_key, wallet_u64(height.saturating_add(10)), 0) {
        Ok(block) => block,
        Err(err) => panic!("Block::new failed for height {height}: {err:?}"),
    }
}

fn store_block(ctx: &DisplayCtx, block: &Block) {
    let bytes = match block.serialize_for_storage() {
        Ok(bytes) => bytes,
        Err(err) => panic!("serialize_for_storage failed: {err:?}"),
    };

    match ctx.db.store_latest_block(&bytes, block.metadata.index) {
        Ok(()) => {}
        Err(err) => panic!("store_latest_block failed: {err:?}"),
    }

    match ctx.db.index_block_by_hash(&block.block_hash, &bytes) {
        Ok(()) => {}
        Err(err) => panic!("index_block_by_hash failed: {err:?}"),
    }

    match ctx.db.set_latest_block_index(block.metadata.index) {
        Ok(()) => {}
        Err(err) => panic!("set_latest_block_index failed: {err:?}"),
    }

    match ctx.db.set_tip_height(block.metadata.index) {
        Ok(()) => {}
        Err(err) => panic!("set_tip_height failed: {err:?}"),
    }
}

fn store_block_at_height(ctx: &DisplayCtx, height: u64) -> Block {
    let prev_hash = if height <= 1 {
        nonzero_hash(1)
    } else {
        nonzero_hash(u8::try_from(height.saturating_sub(1)).unwrap_or(1))
    };
    let block = make_block(height, prev_hash);
    store_block(ctx, &block);
    block
}

fn store_chain(ctx: &DisplayCtx, heights: &[u64]) -> Vec<Block> {
    let mut blocks = Vec::with_capacity(heights.len());
    let mut prev_hash = nonzero_hash(1);

    for height in heights {
        let block = make_block(*height, prev_hash);
        prev_hash = block.block_hash;
        store_block(ctx, &block);
        blocks.push(block);
    }

    blocks
}

fn make_register_kind(seed: u64) -> TxKind {
    let tx = match RegisterNodeTx::new(wallet_u64(seed)) {
        Ok(tx) => tx,
        Err(err) => panic!("RegisterNodeTx::new failed: {err:?}"),
    };

    TxKind::RegisterNode(tx)
}

fn store_batch_for_height(ctx: &DisplayCtx, height: u64, tx_count: usize) {
    let txs = (0usize..tx_count)
        .map(|i| make_register_kind(u64::try_from(i).unwrap_or(0).saturating_add(height * 100)))
        .collect::<Vec<_>>();

    let batch = match TransactionBatch::new(height, 1_700_000_000u64.saturating_add(height), txs) {
        Ok(batch) => batch,
        Err(err) => panic!("TransactionBatch::new failed: {err:?}"),
    };

    let bytes = match batch.serialize() {
        Ok(bytes) => bytes,
        Err(err) => panic!("TransactionBatch::serialize failed: {err:?}"),
    };

    let key = format!("tx_batch_{height:010}");
    match ctx.db.write(
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        key.as_bytes(),
        &bytes,
    ) {
        Ok(()) => {}
        Err(err) => panic!("write batch failed: {err:?}"),
    }
}

fn store_invalid_batch_for_height(ctx: &DisplayCtx, height: u64) {
    let key = format!("tx_batch_{height:010}");
    match ctx.db.write(
        GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
        key.as_bytes(),
        b"not-a-valid-postcard-batch",
    ) {
        Ok(()) => {}
        Err(err) => panic!("write invalid batch failed: {err:?}"),
    }
}

fn set_tip_without_block(ctx: &DisplayCtx, height: u64) {
    match ctx.db.set_tip_height(height) {
        Ok(()) => {}
        Err(err) => panic!("set_tip_height failed: {err:?}"),
    }

    match ctx.db.set_latest_block_index(height) {
        Ok(()) => {}
        Err(err) => panic!("set_latest_block_index failed: {err:?}"),
    }
}

fn call_display(ctx: &DisplayCtx, last_logged_tip: &mut u64, last_minted_height: &mut Option<u64>) {
    let tree = account_tree(ctx);
    ctx.display
        .print_new_blocks_since(&tree, last_logged_tip, last_minted_height);
}

fn next_line(rx: &mut tokio::sync::broadcast::Receiver<String>) -> String {
    match rx.try_recv() {
        Ok(line) => line,
        Err(err) => panic!("expected live console line, got {err:?}"),
    }
}

fn assert_no_line(rx: &mut tokio::sync::broadcast::Receiver<String>) {
    match rx.try_recv() {
        Err(TryRecvError::Empty) => {}
        other => panic!("expected no live console line, got {other:?}"),
    }
}

#[test]
fn blockchain_01_002_orchestration_display_vector_new_defaults_log_sequence_true() {
    let ctx = new_ctx("vector_new_defaults_log_sequence_true");

    assert!(ctx.display.log_sequence);
}

#[test]
fn blockchain_02_002_orchestration_display_vector_no_tip_advance_keeps_cursor() {
    let ctx = new_ctx("vector_no_tip_advance_keeps_cursor");
    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 0);
    assert_eq!(last_minted_height, Some(1));
}

#[test]
fn blockchain_03_002_orchestration_display_edge_no_log_no_subscriber_fast_forwards_tip() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_no_log_no_subscriber_fast_forwards_tip"),
        false,
    );
    set_tip_without_block(&ctx, 5);

    let mut last_logged_tip = 2;
    let mut last_minted_height = Some(5);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 5);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_04_002_orchestration_display_edge_no_log_no_subscriber_no_advance_keeps_minted_marker()
 {
    let ctx = display_with_log_sequence(
        new_ctx("edge_no_log_no_subscriber_no_advance_keeps_minted_marker"),
        false,
    );

    let mut last_logged_tip = 7;
    let mut last_minted_height = Some(7);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 7);
    assert_eq!(last_minted_height, Some(7));
}

#[test]
fn blockchain_05_002_orchestration_display_vector_no_log_with_subscriber_publishes_accepted_line() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_no_log_with_subscriber_publishes_accepted_line"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("accepted:  <"));
    assert!(line.contains("block: 1"));
    assert_eq!(last_logged_tip, 1);
}

#[test]
fn blockchain_06_002_orchestration_display_vector_minted_line_when_last_minted_matches_height() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_minted_line_when_last_minted_matches_height"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("minted:    >"));
    assert!(line.contains("block: 1"));
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_07_002_orchestration_display_vector_accepted_line_when_last_minted_different_height()
{
    let ctx = display_with_log_sequence(
        new_ctx("vector_accepted_line_when_last_minted_different_height"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 2);

    let mut last_logged_tip = 1;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("accepted:  <"));
    assert!(line.contains("block: 2"));
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_08_002_orchestration_display_vector_missing_block_does_not_publish_live_line() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_missing_block_does_not_publish_live_line"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    set_tip_without_block(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 1);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_09_002_orchestration_display_vector_batch_absent_reports_zero_txs() {
    let ctx = display_with_log_sequence(new_ctx("vector_batch_absent_reports_zero_txs"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 0"));
}

#[test]
fn blockchain_10_002_orchestration_display_vector_empty_batch_reports_zero_txs() {
    let ctx = display_with_log_sequence(new_ctx("vector_empty_batch_reports_zero_txs"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    store_batch_for_height(&ctx, 1, 0);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 0"));
}

#[test]
fn blockchain_11_002_orchestration_display_vector_one_tx_batch_reports_one_tx() {
    let ctx = display_with_log_sequence(new_ctx("vector_one_tx_batch_reports_one_tx"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    store_batch_for_height(&ctx, 1, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 1"));
}

#[test]
fn blockchain_12_002_orchestration_display_vector_three_tx_batch_reports_three_txs() {
    let ctx = display_with_log_sequence(new_ctx("vector_three_tx_batch_reports_three_txs"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    store_batch_for_height(&ctx, 1, 3);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 3"));
}

#[test]
fn blockchain_13_002_orchestration_display_fuzz_invalid_batch_bytes_fall_back_to_zero_txs() {
    let ctx = display_with_log_sequence(
        new_ctx("fuzz_invalid_batch_bytes_fall_back_to_zero_txs"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    store_invalid_batch_for_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 0"));
}

#[test]
fn blockchain_14_002_orchestration_display_vector_wrong_batch_key_is_ignored() {
    let ctx = display_with_log_sequence(new_ctx("vector_wrong_batch_key_is_ignored"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    store_batch_for_height(&ctx, 2, 4);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 0"));
}

#[test]
fn blockchain_15_002_orchestration_display_vector_reward_field_matches_halving_for_height() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_reward_field_matches_halving_for_height"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let expected_reward = helper::format_remzar_trim(RewardHalving::get_block_reward(1));
    let line = next_line(&mut rx);
    assert!(line.contains(&format!("reward: {expected_reward}/")));
}

#[test]
fn blockchain_16_002_orchestration_display_vector_remaining_reward_field_matches_schedule() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_remaining_reward_field_matches_schedule"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let remaining_micro = RewardHalving::remaining_reward_supply_micro_after_block(1);
    let remaining_u64 = u64::try_from(remaining_micro).unwrap_or(u64::MAX);
    let expected_left = helper::format_remzar_trim_one_decimal(remaining_u64);

    let line = next_line(&mut rx);
    assert!(line.contains(&format!("/{expected_left}")));
}

#[test]
fn blockchain_17_002_orchestration_display_vector_hash_is_ellipsized_in_live_line() {
    let ctx = display_with_log_sequence(new_ctx("vector_hash_is_ellipsized_in_live_line"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("hash: "));
    assert!(line.contains("..."));
}

#[test]
fn blockchain_18_002_orchestration_display_vector_line_contains_utc_z_timestamp_shape() {
    let ctx =
        display_with_log_sequence(new_ctx("vector_line_contains_utc_z_timestamp_shape"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains('T'));
    assert!(line.contains('Z'));
}

#[test]
fn blockchain_19_002_orchestration_display_property_two_blocks_publish_two_lines_in_order() {
    let ctx = display_with_log_sequence(
        new_ctx("property_two_blocks_publish_two_lines_in_order"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let first = next_line(&mut rx);
    let second = next_line(&mut rx);

    assert!(first.contains("block: 1"));
    assert!(second.contains("block: 2"));
    assert_eq!(last_logged_tip, 2);
}

#[test]
fn blockchain_20_002_orchestration_display_property_three_blocks_publish_three_lines_in_order() {
    let ctx = display_with_log_sequence(
        new_ctx("property_three_blocks_publish_three_lines_in_order"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let first = next_line(&mut rx);
    let second = next_line(&mut rx);
    let third = next_line(&mut rx);

    assert!(first.contains("block: 1"));
    assert!(second.contains("block: 2"));
    assert!(third.contains("block: 3"));
    assert_eq!(last_logged_tip, 3);
}

#[test]
fn blockchain_21_002_orchestration_display_property_starts_from_last_logged_plus_one() {
    let ctx =
        display_with_log_sequence(new_ctx("property_starts_from_last_logged_plus_one"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);

    let mut last_logged_tip = 1;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let first = next_line(&mut rx);
    let second = next_line(&mut rx);

    assert!(first.contains("block: 2"));
    assert!(second.contains("block: 3"));
    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 3);
}

#[test]
fn blockchain_22_002_orchestration_display_property_minted_only_for_matching_height_in_range() {
    let ctx = display_with_log_sequence(
        new_ctx("property_minted_only_for_matching_height_in_range"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(2);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let one = next_line(&mut rx);
    let two = next_line(&mut rx);
    let three = next_line(&mut rx);

    assert!(one.contains("accepted:  <"));
    assert!(one.contains("block: 1"));
    assert!(two.contains("minted:    >"));
    assert!(two.contains("block: 2"));
    assert!(three.contains("accepted:  <"));
    assert!(three.contains("block: 3"));
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_23_002_orchestration_display_edge_last_logged_ahead_of_tip_does_not_rewind() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_last_logged_ahead_of_tip_does_not_rewind"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 2);

    let mut last_logged_tip = 9;
    let mut last_minted_height = Some(9);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 9);
    assert_eq!(last_minted_height, Some(9));
}

#[test]
fn blockchain_24_002_orchestration_display_edge_tip_equal_last_logged_does_not_publish() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_tip_equal_last_logged_does_not_publish"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 2);

    let mut last_logged_tip = 2;
    let mut last_minted_height = Some(2);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 2);
    assert_eq!(last_minted_height, Some(2));
}

#[test]
fn blockchain_25_002_orchestration_display_vector_terminal_only_path_updates_cursor() {
    let ctx = new_ctx("vector_terminal_only_path_updates_cursor");

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 1);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_26_002_orchestration_display_vector_terminal_only_missing_block_updates_cursor() {
    let ctx = new_ctx("vector_terminal_only_missing_block_updates_cursor");

    set_tip_without_block(&ctx, 3);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(3);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 3);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_27_002_orchestration_display_vector_live_console_receiver_count_controls_publish() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_live_console_receiver_count_controls_publish"),
        false,
    );

    assert_eq!(ctx.bus.live_chain_tx.receiver_count(), 0);

    let _rx = ctx.bus.subscribe_live_chain();

    assert_eq!(ctx.bus.live_chain_tx.receiver_count(), 1);
}

#[test]
fn blockchain_28_002_orchestration_display_adversarial_drop_receiver_before_call_prevents_publish()
{
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_drop_receiver_before_call_prevents_publish"),
        false,
    );

    let rx = ctx.bus.subscribe_live_chain();
    drop(rx);

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 1);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_29_002_orchestration_display_adversarial_two_receivers_both_receive_same_line() {
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_two_receivers_both_receive_same_line"),
        false,
    );

    let mut rx1 = ctx.bus.subscribe_live_chain();
    let mut rx2 = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let one = next_line(&mut rx1);
    let two = next_line(&mut rx2);

    assert_eq!(one, two);
    assert!(one.contains("minted:    >"));
}

#[test]
fn blockchain_30_002_orchestration_display_adversarial_old_receiver_gets_line_after_late_subscriber_misses_it()
 {
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_old_receiver_gets_line_after_late_subscriber_misses_it"),
        false,
    );

    let mut old_rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let mut late_rx = ctx.bus.subscribe_live_chain();

    let old_line = next_line(&mut old_rx);
    assert!(old_line.contains("block: 1"));
    assert_no_line(&mut late_rx);
}

#[test]
fn blockchain_31_002_orchestration_display_fuzz_many_invalid_batch_payloads_report_zero_txs() {
    let payloads = [
        Vec::new(),
        vec![0u8],
        vec![1u8, 2, 3, 4],
        vec![255u8; 64],
        b"definitely-not-a-batch".to_vec(),
    ];

    for (idx, payload) in payloads.iter().enumerate() {
        let ctx = display_with_log_sequence(
            new_ctx(&format!(
                "fuzz_many_invalid_batch_payloads_report_zero_txs_{idx}"
            )),
            false,
        );
        let mut rx = ctx.bus.subscribe_live_chain();

        store_block_at_height(&ctx, 1);

        let key = "tx_batch_0000000001";
        match ctx.db.write(
            GlobalConfiguration::TRANSACTION_BATCH_COLUMN_NAME,
            key.as_bytes(),
            payload,
        ) {
            Ok(()) => {}
            Err(err) => panic!("write fuzz payload failed: {err:?}"),
        }

        let mut last_logged_tip = 0;
        let mut last_minted_height = None;

        call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

        let line = next_line(&mut rx);
        assert!(line.contains("txs: 0"));
    }
}

#[test]
fn blockchain_32_002_orchestration_display_load_ten_blocks_publish_ten_lines() {
    let ctx = display_with_log_sequence(new_ctx("load_ten_blocks_publish_ten_lines"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    let heights = (1u64..=10u64).collect::<Vec<_>>();
    store_chain(&ctx, &heights);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=10u64 {
        let line = next_line(&mut rx);
        assert!(line.contains(&format!("block: {height}")));
    }

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 10);
}

#[test]
fn blockchain_33_002_orchestration_display_load_twenty_blocks_from_middle_publish_remaining_half() {
    let ctx = display_with_log_sequence(
        new_ctx("load_twenty_blocks_from_middle_publish_remaining_half"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let heights = (1u64..=20u64).collect::<Vec<_>>();
    store_chain(&ctx, &heights);

    let mut last_logged_tip = 10;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 11u64..=20u64 {
        let line = next_line(&mut rx);
        assert!(line.contains(&format!("block: {height}")));
    }

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 20);
}

#[test]
fn blockchain_34_002_orchestration_display_load_many_batches_preserve_tx_counts_per_height() {
    let ctx = display_with_log_sequence(
        new_ctx("load_many_batches_preserve_tx_counts_per_height"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3, 4, 5]);
    for height in 1u64..=5u64 {
        store_batch_for_height(&ctx, height, usize::try_from(height).unwrap_or(0));
    }

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=5u64 {
        let line = next_line(&mut rx);
        assert!(line.contains(&format!("block: {height}")));
        assert!(line.contains(&format!("txs: {height}")));
    }
}

#[test]
fn blockchain_35_002_orchestration_display_property_repeated_call_after_logging_publishes_nothing()
{
    let ctx = display_with_log_sequence(
        new_ctx("property_repeated_call_after_logging_publishes_nothing"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let first = next_line(&mut rx);
    assert!(first.contains("block: 1"));

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    assert_no_line(&mut rx);
}

#[test]
fn blockchain_36_002_orchestration_display_property_cursor_can_resume_after_new_tip_added() {
    let ctx = display_with_log_sequence(
        new_ctx("property_cursor_can_resume_after_new_tip_added"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1]);
    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let first = next_line(&mut rx);
    assert!(first.contains("block: 1"));

    store_chain(&ctx, &[2]);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let second = next_line(&mut rx);
    assert!(second.contains("block: 2"));
    assert_no_line(&mut rx);
}

#[test]
fn blockchain_37_002_orchestration_display_vector_minted_marker_cleared_even_when_matching_block_missing()
 {
    let ctx = display_with_log_sequence(
        new_ctx("vector_minted_marker_cleared_even_when_matching_block_missing"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    set_tip_without_block(&ctx, 9);

    let mut last_logged_tip = 8;
    let mut last_minted_height = Some(9);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 9);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_38_002_orchestration_display_vector_high_height_block_formats_height_correctly() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_high_height_block_formats_height_correctly"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 123);

    let mut last_logged_tip = 122;
    let mut last_minted_height = Some(123);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("block: 123"));
    assert!(line.contains("minted:    >"));
}

#[test]
fn blockchain_39_002_orchestration_display_property_live_line_has_required_fields() {
    let ctx = display_with_log_sequence(new_ctx("property_live_line_has_required_fields"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    store_batch_for_height(&ctx, 1, 2);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("minted:"));
    assert!(line.contains("block:"));
    assert!(line.contains("txs:"));
    assert!(line.contains("reward:"));
    assert!(line.contains("hash:"));
}

#[test]
fn blockchain_40_002_orchestration_display_load_broadcast_line_to_multiple_receivers_after_many_blocks()
 {
    let ctx = display_with_log_sequence(
        new_ctx("load_broadcast_line_to_multiple_receivers_after_many_blocks"),
        false,
    );

    let mut rx1 = ctx.bus.subscribe_live_chain();
    let mut rx2 = ctx.bus.subscribe_live_chain();
    let mut rx3 = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(3);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=3u64 {
        let one = next_line(&mut rx1);
        let two = next_line(&mut rx2);
        let three = next_line(&mut rx3);

        assert_eq!(one, two);
        assert_eq!(two, three);
        assert!(one.contains(&format!("block: {height}")));
    }

    assert_no_line(&mut rx1);
    assert_no_line(&mut rx2);
    assert_no_line(&mut rx3);
}

#[test]
fn blockchain_41_002_orchestration_display_edge_no_log_no_subscriber_tip_equal_keeps_state() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_no_log_no_subscriber_tip_equal_keeps_state"),
        false,
    );

    set_tip_without_block(&ctx, 4);

    let mut last_logged_tip = 4;
    let mut last_minted_height = Some(4);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 4);
    assert_eq!(last_minted_height, Some(4));
}

#[test]
fn blockchain_42_002_orchestration_display_edge_no_log_no_subscriber_last_ahead_does_not_rewind() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_no_log_no_subscriber_last_ahead_does_not_rewind"),
        false,
    );

    set_tip_without_block(&ctx, 3);

    let mut last_logged_tip = 9;
    let mut last_minted_height = Some(9);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 9);
    assert_eq!(last_minted_height, Some(9));
}

#[test]
fn blockchain_43_002_orchestration_display_edge_no_log_no_subscriber_fast_forwards_large_gap() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_no_log_no_subscriber_fast_forwards_large_gap"),
        false,
    );

    set_tip_without_block(&ctx, 1_000);

    let mut last_logged_tip = 7;
    let mut last_minted_height = Some(1_000);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 1_000);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_44_002_orchestration_display_edge_subscriber_missing_range_publishes_nothing_but_advances()
 {
    let ctx = display_with_log_sequence(
        new_ctx("edge_subscriber_missing_range_publishes_nothing_but_advances"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    set_tip_without_block(&ctx, 6);

    let mut last_logged_tip = 3;
    let mut last_minted_height = Some(6);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 6);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_45_002_orchestration_display_edge_missing_first_height_then_existing_second_publishes_second()
 {
    let ctx = display_with_log_sequence(
        new_ctx("edge_missing_first_height_then_existing_second_publishes_second"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 2);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("block: 2"));
    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 2);
}

#[test]
fn blockchain_46_002_orchestration_display_edge_existing_first_then_missing_later_publishes_only_first()
 {
    let ctx = display_with_log_sequence(
        new_ctx("edge_existing_first_then_missing_later_publishes_only_first"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    set_tip_without_block(&ctx, 3);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(3);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("block: 1"));
    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 3);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_47_002_orchestration_display_vector_five_tx_batch_reports_five_txs() {
    let ctx = display_with_log_sequence(new_ctx("vector_five_tx_batch_reports_five_txs"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    store_batch_for_height(&ctx, 1, 5);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 5"));
}

#[test]
fn blockchain_48_002_orchestration_display_vector_eight_tx_batch_reports_eight_txs() {
    let ctx = display_with_log_sequence(new_ctx("vector_eight_tx_batch_reports_eight_txs"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    store_batch_for_height(&ctx, 1, 8);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 8"));
}

#[test]
fn blockchain_49_002_orchestration_display_fuzz_mixed_valid_and_invalid_batches_keep_per_height_counts()
 {
    let ctx = display_with_log_sequence(
        new_ctx("fuzz_mixed_valid_and_invalid_batches_keep_per_height_counts"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2]);
    store_batch_for_height(&ctx, 1, 2);
    store_invalid_batch_for_height(&ctx, 2);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let one = next_line(&mut rx);
    let two = next_line(&mut rx);

    assert!(one.contains("block: 1"));
    assert!(one.contains("txs: 2"));
    assert!(two.contains("block: 2"));
    assert!(two.contains("txs: 0"));
}

#[test]
fn blockchain_50_002_orchestration_display_property_only_matching_last_height_is_minted() {
    let ctx = display_with_log_sequence(
        new_ctx("property_only_matching_last_height_is_minted"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(3);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let one = next_line(&mut rx);
    let two = next_line(&mut rx);
    let three = next_line(&mut rx);

    assert!(one.contains("accepted:  <"));
    assert!(two.contains("accepted:  <"));
    assert!(three.contains("minted:    >"));
    assert!(three.contains("block: 3"));
}

#[test]
fn blockchain_51_002_orchestration_display_property_minted_height_below_start_is_ignored() {
    let ctx = display_with_log_sequence(
        new_ctx("property_minted_height_below_start_is_ignored"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);

    let mut last_logged_tip = 1;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let two = next_line(&mut rx);
    let three = next_line(&mut rx);

    assert!(two.contains("accepted:  <"));
    assert!(two.contains("block: 2"));
    assert!(three.contains("accepted:  <"));
    assert!(three.contains("block: 3"));
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_52_002_orchestration_display_property_minted_height_above_tip_is_ignored_and_cleared()
{
    let ctx = display_with_log_sequence(
        new_ctx("property_minted_height_above_tip_is_ignored_and_cleared"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(99);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let one = next_line(&mut rx);
    let two = next_line(&mut rx);

    assert!(one.contains("accepted:  <"));
    assert!(two.contains("accepted:  <"));
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_53_002_orchestration_display_vector_live_line_contains_reward_separator_and_hash() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_live_line_contains_reward_separator_and_hash"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("reward: "));
    assert!(line.contains('/'));
    assert!(line.contains("hash: "));
}

#[test]
fn blockchain_54_002_orchestration_display_property_cursor_resumes_after_new_block_added() {
    let ctx = display_with_log_sequence(
        new_ctx("property_cursor_resumes_after_new_block_added"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let first = next_line(&mut rx);
    assert!(first.contains("block: 1"));

    store_block_at_height(&ctx, 2);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let second = next_line(&mut rx);
    assert!(second.contains("block: 2"));
    assert_no_line(&mut rx);
}

#[test]
fn blockchain_55_002_orchestration_display_adversarial_late_subscriber_only_receives_future_lines()
{
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_late_subscriber_only_receives_future_lines"),
        false,
    );

    let mut early_rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let first = next_line(&mut early_rx);
    assert!(first.contains("block: 1"));

    let mut late_rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 2);
    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let early_second = next_line(&mut early_rx);
    let late_second = next_line(&mut late_rx);

    assert_eq!(early_second, late_second);
    assert!(late_second.contains("block: 2"));
}

#[test]
fn blockchain_56_002_orchestration_display_adversarial_two_displays_same_bus_can_publish_same_block()
 {
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_two_displays_same_bus_can_publish_same_block"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let mut second_display = OrchestrationDisplay::new(Arc::clone(&ctx.db), ctx.bus.clone());
    second_display.log_sequence = false;

    store_block_at_height(&ctx, 1);

    let mut first_last = 0;
    let mut first_minted = None;
    let mut second_last = 0;
    let mut second_minted = Some(1);

    let tree = account_tree(&ctx);
    ctx.display
        .print_new_blocks_since(&tree, &mut first_last, &mut first_minted);
    second_display.print_new_blocks_since(&tree, &mut second_last, &mut second_minted);

    let accepted = next_line(&mut rx);
    let minted = next_line(&mut rx);

    assert!(accepted.contains("accepted:  <"));
    assert!(minted.contains("minted:    >"));
}

#[test]
fn blockchain_57_002_orchestration_display_vector_log_sequence_can_be_disabled() {
    let mut ctx = new_ctx("vector_log_sequence_can_be_disabled");

    assert!(ctx.display.log_sequence);

    ctx.display.log_sequence = false;

    assert!(!ctx.display.log_sequence);
}

#[test]
fn blockchain_58_002_orchestration_display_vector_log_sequence_reenabled_still_publishes_to_subscriber()
 {
    let mut ctx = new_ctx("vector_log_sequence_reenabled_still_publishes_to_subscriber");
    ctx.display.log_sequence = false;
    ctx.display.log_sequence = true;

    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("minted:    >"));
}

#[test]
fn blockchain_59_002_orchestration_display_adversarial_dropped_receiver_returns_to_fast_forward_mode()
 {
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_dropped_receiver_returns_to_fast_forward_mode"),
        false,
    );

    let rx = ctx.bus.subscribe_live_chain();
    assert_eq!(ctx.bus.live_chain_tx.receiver_count(), 1);
    drop(rx);
    assert_eq!(ctx.bus.live_chain_tx.receiver_count(), 0);

    set_tip_without_block(&ctx, 12);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(12);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 12);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_60_002_orchestration_display_vector_receiver_count_tracks_three_subscribers() {
    let ctx = new_ctx("vector_receiver_count_tracks_three_subscribers");

    assert_eq!(ctx.bus.live_chain_tx.receiver_count(), 0);

    let _rx1 = ctx.bus.subscribe_live_chain();
    let _rx2 = ctx.bus.subscribe_live_chain();
    let _rx3 = ctx.bus.subscribe_live_chain();

    assert_eq!(ctx.bus.live_chain_tx.receiver_count(), 3);
}

#[test]
fn blockchain_61_002_orchestration_display_vector_console_bus_direct_publish_reaches_subscriber() {
    let ctx = new_ctx("vector_console_bus_direct_publish_reaches_subscriber");
    let mut rx = ctx.bus.subscribe_live_chain();

    ctx.bus
        .publish_live_chain_line("manual orchestration display test line".to_owned());

    let line = next_line(&mut rx);
    assert_eq!(line, "manual orchestration display test line");
}

#[test]
fn blockchain_62_002_orchestration_display_vector_direct_bus_publish_does_not_affect_display_cursor()
 {
    let ctx = display_with_log_sequence(
        new_ctx("vector_direct_bus_publish_does_not_affect_display_cursor"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    ctx.bus.publish_live_chain_line("manual".to_owned());
    let manual = next_line(&mut rx);
    assert_eq!(manual, "manual");

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 0);
    assert_eq!(last_minted_height, Some(1));
}

#[test]
fn blockchain_63_002_orchestration_display_property_second_call_without_new_tip_publishes_nothing()
{
    let ctx = display_with_log_sequence(
        new_ctx("property_second_call_without_new_tip_publishes_nothing"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let first = next_line(&mut rx);
    assert!(first.contains("block: 1"));

    last_minted_height = Some(1);
    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_minted_height, Some(1));
}

#[test]
fn blockchain_64_002_orchestration_display_vector_timestamp_prefix_splits_from_payload() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_timestamp_prefix_splits_from_payload"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    let mut parts = line.split("  ");
    let ts = match parts.next() {
        Some(v) => v,
        None => panic!("timestamp missing"),
    };

    assert!(ts.contains('T'));
    assert!(ts.ends_with('Z'));
}

#[test]
fn blockchain_65_002_orchestration_display_vector_accepted_spacing_is_exact_plain_line_shape() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_accepted_spacing_is_exact_plain_line_shape"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("accepted:  <  |"));
}

#[test]
fn blockchain_66_002_orchestration_display_vector_minted_spacing_is_exact_plain_line_shape() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_minted_spacing_is_exact_plain_line_shape"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("minted:    >  |"));
}

#[test]
fn blockchain_67_002_orchestration_display_vector_reward_field_has_expected_slash_separator() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_reward_field_has_expected_slash_separator"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    let reward = extra_display_field(&line, "reward:");
    assert!(reward.contains('/'));
}

#[test]
fn blockchain_68_002_orchestration_display_vector_hash_field_is_ellipsized_to_head_tail_shape() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_hash_field_is_ellipsized_to_head_tail_shape"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    let hash = extra_display_field(&line, "hash:");

    assert_eq!(hash.len(), 67);
    assert!(hash.contains("..."));
}

#[test]
fn blockchain_69_002_orchestration_display_property_hash_field_is_hex_and_dots_only() {
    let ctx = display_with_log_sequence(new_ctx("property_hash_field_is_hex_and_dots_only"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    let hash = extra_display_field(&line, "hash:");

    assert!(
        hash.as_bytes()
            .iter()
            .all(|b| matches!(*b, b'0'..=b'9' | b'a'..=b'f' | b'.'))
    );
}

#[test]
fn blockchain_70_002_orchestration_display_vector_high_height_with_batch_formats_height_and_txs() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_high_height_with_batch_formats_height_and_txs"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 64);
    store_batch_for_height(&ctx, 64, 7);

    let mut last_logged_tip = 63;
    let mut last_minted_height = Some(64);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("block: 64"));
    assert!(line.contains("txs: 7"));
    assert!(line.contains("minted:    >"));
}

#[test]
fn blockchain_71_002_orchestration_display_property_cursor_prevents_replay_after_large_range() {
    let ctx = display_with_log_sequence(
        new_ctx("property_cursor_prevents_replay_after_large_range"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let heights = (1u64..=6u64).collect::<Vec<_>>();
    store_chain(&ctx, &heights);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=6u64 {
        let line = next_line(&mut rx);
        assert!(line.contains(&format!("block: {height}")));
    }

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    assert_no_line(&mut rx);
}

#[test]
fn blockchain_72_002_orchestration_display_edge_tip_zero_with_minted_marker_does_not_clear_marker()
{
    let ctx = display_with_log_sequence(
        new_ctx("edge_tip_zero_with_minted_marker_does_not_clear_marker"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 0);
    assert_eq!(last_minted_height, Some(1));
}

#[test]
fn blockchain_73_002_orchestration_display_edge_tip_advance_without_blocks_clears_marker_with_subscriber()
 {
    let ctx = display_with_log_sequence(
        new_ctx("edge_tip_advance_without_blocks_clears_marker_with_subscriber"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    set_tip_without_block(&ctx, 2);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(2);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 2);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_74_002_orchestration_display_vector_tree_reward_mismatch_path_still_publishes_line() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_tree_reward_mismatch_path_still_publishes_line"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 2);

    let mut last_logged_tip = 1;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("accepted:  <"));
    assert!(line.contains("block: 2"));
}

#[test]
fn blockchain_75_002_orchestration_display_load_mixed_missing_and_present_blocks_publish_present_only()
 {
    let ctx = display_with_log_sequence(
        new_ctx("load_mixed_missing_and_present_blocks_publish_present_only"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 2);
    store_block_at_height(&ctx, 4);
    set_tip_without_block(&ctx, 5);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(4);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let two = next_line(&mut rx);
    let four = next_line(&mut rx);

    assert!(two.contains("block: 2"));
    assert!(two.contains("accepted:  <"));
    assert!(four.contains("block: 4"));
    assert!(four.contains("minted:    >"));
    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 5);
}

#[test]
fn blockchain_76_002_orchestration_display_edge_genesis_height_zero_block_never_prints_when_tip_zero()
 {
    let ctx = display_with_log_sequence(
        new_ctx("edge_genesis_height_zero_block_never_prints_when_tip_zero"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let genesis = make_block(0, [0u8; 64]);
    store_block(&ctx, &genesis);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(0);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 0);
    assert_eq!(last_minted_height, Some(0));
}

#[test]
fn blockchain_77_002_orchestration_display_edge_last_logged_u64_max_does_not_rewind_or_publish() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_last_logged_u64_max_does_not_rewind_or_publish"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    set_tip_without_block(&ctx, 10);

    let mut last_logged_tip = u64::MAX;
    let mut last_minted_height = Some(u64::MAX);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, u64::MAX);
    assert_eq!(last_minted_height, Some(u64::MAX));
}

#[test]
fn blockchain_78_002_orchestration_display_edge_fast_forward_to_u64_max_without_subscriber() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_fast_forward_to_u64_max_without_subscriber"),
        false,
    );

    set_tip_without_block(&ctx, u64::MAX);

    let mut last_logged_tip = u64::MAX.saturating_sub(1);
    let mut last_minted_height = Some(u64::MAX);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, u64::MAX);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_79_002_orchestration_display_edge_subscriber_one_step_to_u64_max_missing_block() {
    let ctx = display_with_log_sequence(
        new_ctx("edge_subscriber_one_step_to_u64_max_missing_block"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    set_tip_without_block(&ctx, u64::MAX);

    let mut last_logged_tip = u64::MAX.saturating_sub(1);
    let mut last_minted_height = Some(u64::MAX);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, u64::MAX);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_80_002_orchestration_display_load_twenty_five_blocks_publish_twenty_five_lines() {
    let ctx = display_with_log_sequence(
        new_ctx("load_twenty_five_blocks_publish_twenty_five_lines"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let heights = (1u64..=25u64).collect::<Vec<_>>();
    store_chain(&ctx, &heights);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(25);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=25u64 {
        let line = next_line(&mut rx);
        assert!(line.contains(&format!("block: {height}")));

        if height == 25 {
            assert!(line.contains("minted:    >"));
        } else {
            assert!(line.contains("accepted:  <"));
        }
    }

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 25);
}

#[test]
fn blockchain_81_002_orchestration_display_property_distinct_heights_have_distinct_hash_fields() {
    let ctx = display_with_log_sequence(
        new_ctx("property_distinct_heights_have_distinct_hash_fields"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let one = next_line(&mut rx);
    let two = next_line(&mut rx);

    let hash_one = extra_display_field(&one, "hash:");
    let hash_two = extra_display_field(&two, "hash:");

    assert_ne!(hash_one, hash_two);
}

#[test]
fn blockchain_82_002_orchestration_display_property_every_line_in_range_has_utc_shape() {
    let ctx =
        display_with_log_sequence(new_ctx("property_every_line_in_range_has_utc_shape"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for _ in 0usize..3usize {
        let line = next_line(&mut rx);
        let ts = match line.split("  ").next() {
            Some(v) => v,
            None => panic!("timestamp missing"),
        };

        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
    }
}

#[test]
fn blockchain_83_002_orchestration_display_property_absent_batches_report_zero_for_each_height() {
    let ctx = display_with_log_sequence(
        new_ctx("property_absent_batches_report_zero_for_each_height"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=3u64 {
        let line = next_line(&mut rx);
        assert!(line.contains(&format!("block: {height}")));
        assert!(line.contains("txs: 0"));
    }
}

#[test]
fn blockchain_84_002_orchestration_display_property_mixed_batch_counts_are_reported_per_height() {
    let ctx = display_with_log_sequence(
        new_ctx("property_mixed_batch_counts_are_reported_per_height"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3]);
    store_batch_for_height(&ctx, 1, 0);
    store_batch_for_height(&ctx, 2, 2);
    store_batch_for_height(&ctx, 3, 4);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let one = next_line(&mut rx);
    let two = next_line(&mut rx);
    let three = next_line(&mut rx);

    assert!(one.contains("txs: 0"));
    assert!(two.contains("txs: 2"));
    assert!(three.contains("txs: 4"));
}

#[test]
fn blockchain_85_002_orchestration_display_property_starting_from_middle_keeps_order() {
    let ctx =
        display_with_log_sequence(new_ctx("property_starting_from_middle_keeps_order"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    let heights = (1u64..=5u64).collect::<Vec<_>>();
    store_chain(&ctx, &heights);

    let mut last_logged_tip = 2;
    let mut last_minted_height = Some(5);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 3u64..=5u64 {
        let line = next_line(&mut rx);
        assert!(line.contains(&format!("block: {height}")));

        if height == 5 {
            assert!(line.contains("minted:    >"));
        }
    }

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 5);
}

#[test]
fn blockchain_86_002_orchestration_display_vector_terminal_only_no_subscriber_updates_cursor() {
    let ctx = new_ctx("vector_terminal_only_no_subscriber_updates_cursor");

    assert_eq!(ctx.bus.live_chain_tx.receiver_count(), 0);

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 1);
    assert_eq!(last_minted_height, None);
}

#[test]
fn blockchain_87_002_orchestration_display_vector_subscriber_before_display_construction_receives_line()
 {
    let db = match new_db("vector_subscriber_before_display_construction_receives_line") {
        Ok(db) => db,
        Err(err) => panic!("failed to create db: {err}"),
    };

    let bus = ConsoleBus::new();
    let mut rx = bus.subscribe_live_chain();

    let mut display = OrchestrationDisplay::new(Arc::clone(&db), bus.clone());
    display.log_sequence = false;

    let ctx = DisplayCtx { db, display, bus };

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("minted:    >"));
    assert!(line.contains("block: 1"));
}

#[test]
fn blockchain_88_002_orchestration_display_adversarial_independent_cursors_can_publish_different_classifications()
 {
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_independent_cursors_can_publish_different_classifications"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let mut display_b = OrchestrationDisplay::new(Arc::clone(&ctx.db), ctx.bus.clone());
    display_b.log_sequence = false;

    store_block_at_height(&ctx, 1);

    let mut last_a = 0;
    let mut minted_a = Some(1);
    let mut last_b = 0;
    let mut minted_b = None;

    let tree = account_tree(&ctx);
    ctx.display
        .print_new_blocks_since(&tree, &mut last_a, &mut minted_a);
    display_b.print_new_blocks_since(&tree, &mut last_b, &mut minted_b);

    let line_a = next_line(&mut rx);
    let line_b = next_line(&mut rx);

    assert!(line_a.contains("minted:    >"));
    assert!(line_b.contains("accepted:  <"));
}

#[test]
fn blockchain_89_002_orchestration_display_adversarial_receiver_drop_after_first_line_does_not_block_next_call()
 {
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_receiver_drop_after_first_line_does_not_block_next_call"),
        false,
    );

    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let line = next_line(&mut rx);
    assert!(line.contains("block: 1"));

    drop(rx);

    store_block_at_height(&ctx, 2);
    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    assert_eq!(last_logged_tip, 2);
}

#[test]
fn blockchain_90_002_orchestration_display_fuzz_invalid_batch_at_high_height_reports_zero() {
    let ctx = display_with_log_sequence(
        new_ctx("fuzz_invalid_batch_at_high_height_reports_zero"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 77);
    store_invalid_batch_for_height(&ctx, 77);

    let mut last_logged_tip = 76;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("block: 77"));
    assert!(line.contains("txs: 0"));
}

#[test]
fn blockchain_91_002_orchestration_display_property_old_minted_marker_not_reused_for_later_tip() {
    let ctx = display_with_log_sequence(
        new_ctx("property_old_minted_marker_not_reused_for_later_tip"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(1);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let first = next_line(&mut rx);
    assert!(first.contains("minted:    >"));
    assert_eq!(last_minted_height, None);

    store_block_at_height(&ctx, 2);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);
    let second = next_line(&mut rx);
    assert!(second.contains("accepted:  <"));
    assert!(second.contains("block: 2"));
}

#[test]
fn blockchain_92_002_orchestration_display_vector_display_uses_formatted_batch_key_not_block_batch_key()
 {
    let ctx = display_with_log_sequence(
        new_ctx("vector_display_uses_formatted_batch_key_not_block_batch_key"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let _block = extra_display_store_custom_batch_key_block(&ctx, 1, Some("custom_key".to_owned()));
    store_batch_for_height(&ctx, 1, 2);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 2"));
}

#[test]
fn blockchain_93_002_orchestration_display_vector_custom_only_batch_key_is_ignored_by_display() {
    let ctx = display_with_log_sequence(
        new_ctx("vector_custom_only_batch_key_is_ignored_by_display"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let _block =
        extra_display_store_custom_batch_key_block(&ctx, 1, Some("custom_only".to_owned()));
    extra_display_store_batch_under_key(&ctx, "custom_only", 1, 3);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 0"));
}

#[test]
fn blockchain_94_002_orchestration_display_vector_formatted_batch_key_wins_even_when_custom_batch_exists()
 {
    let ctx = display_with_log_sequence(
        new_ctx("vector_formatted_batch_key_wins_even_when_custom_batch_exists"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let _block = extra_display_store_custom_batch_key_block(&ctx, 1, Some("custom_key".to_owned()));
    extra_display_store_batch_under_key(&ctx, "custom_key", 1, 9);
    store_batch_for_height(&ctx, 1, 4);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let line = next_line(&mut rx);
    assert!(line.contains("txs: 4"));
}

#[test]
fn blockchain_95_002_orchestration_display_vector_reward_comes_from_schedule_not_block_reward_field()
 {
    let ctx = display_with_log_sequence(
        new_ctx("vector_reward_comes_from_schedule_not_block_reward_field"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    let meta = BlockMetadata::new(
        1,
        1_700_000_001,
        nonzero_hash(95),
        nonzero_hash(96),
        nonzero_sig(97),
        None,
        GlobalConfiguration::MIN_BLOCK_SIZE,
    );

    let block = match Block::new(
        meta,
        Some("tx_batch_0000000001".to_owned()),
        wallet_u64(95),
        123_456_789,
    ) {
        Ok(block) => block,
        Err(err) => panic!("Block::new failed: {err:?}"),
    };

    store_block(&ctx, &block);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let expected = helper::format_remzar_trim(RewardHalving::get_block_reward(1));
    let line = next_line(&mut rx);

    assert!(line.contains(&format!("reward: {expected}/")));
    assert!(!line.contains("123456789"));
}

#[test]
fn blockchain_96_002_orchestration_display_edge_minted_marker_for_missing_height_is_cleared_after_tip_advance()
 {
    let ctx = display_with_log_sequence(
        new_ctx("edge_minted_marker_for_missing_height_is_cleared_after_tip_advance"),
        false,
    );
    let mut rx = ctx.bus.subscribe_live_chain();

    store_block_at_height(&ctx, 1);
    set_tip_without_block(&ctx, 4);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(4);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    let first = next_line(&mut rx);
    assert!(first.contains("block: 1"));
    assert_eq!(last_logged_tip, 4);
    assert_eq!(last_minted_height, None);
    assert_no_line(&mut rx);
}

#[test]
fn blockchain_97_002_orchestration_display_adversarial_four_receivers_get_identical_sequence() {
    let ctx = display_with_log_sequence(
        new_ctx("adversarial_four_receivers_get_identical_sequence"),
        false,
    );

    let mut rx1 = ctx.bus.subscribe_live_chain();
    let mut rx2 = ctx.bus.subscribe_live_chain();
    let mut rx3 = ctx.bus.subscribe_live_chain();
    let mut rx4 = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2]);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(2);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=2u64 {
        let one = next_line(&mut rx1);
        let two = next_line(&mut rx2);
        let three = next_line(&mut rx3);
        let four = next_line(&mut rx4);

        assert_eq!(one, two);
        assert_eq!(two, three);
        assert_eq!(three, four);
        assert!(one.contains(&format!("block: {height}")));
    }
}

#[test]
fn blockchain_98_002_orchestration_display_load_thirty_blocks_no_batches_all_zero_txs() {
    let ctx =
        display_with_log_sequence(new_ctx("load_thirty_blocks_no_batches_all_zero_txs"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    let heights = (1u64..=30u64).collect::<Vec<_>>();
    store_chain(&ctx, &heights);

    let mut last_logged_tip = 0;
    let mut last_minted_height = None;

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=30u64 {
        let line = next_line(&mut rx);
        assert!(line.contains(&format!("block: {height}")));
        assert!(line.contains("txs: 0"));
    }

    assert_eq!(last_logged_tip, 30);
}

#[test]
fn blockchain_99_002_orchestration_display_load_two_receivers_thirty_blocks_same_sequence() {
    let ctx = display_with_log_sequence(
        new_ctx("load_two_receivers_thirty_blocks_same_sequence"),
        false,
    );

    let mut rx1 = ctx.bus.subscribe_live_chain();
    let mut rx2 = ctx.bus.subscribe_live_chain();

    let heights = (1u64..=30u64).collect::<Vec<_>>();
    store_chain(&ctx, &heights);

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(30);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=30u64 {
        let one = next_line(&mut rx1);
        let two = next_line(&mut rx2);

        assert_eq!(one, two);
        assert!(one.contains(&format!("block: {height}")));
    }

    assert_no_line(&mut rx1);
    assert_no_line(&mut rx2);
}

#[test]
fn blockchain_100_002_orchestration_display_load_final_mixed_counts_and_minted_tail() {
    let ctx = display_with_log_sequence(new_ctx("load_final_mixed_counts_and_minted_tail"), false);
    let mut rx = ctx.bus.subscribe_live_chain();

    store_chain(&ctx, &[1, 2, 3, 4, 5, 6]);

    for height in 1u64..=6u64 {
        let count = usize::try_from(height % 3).unwrap_or(0);
        store_batch_for_height(&ctx, height, count);
    }

    let mut last_logged_tip = 0;
    let mut last_minted_height = Some(6);

    call_display(&ctx, &mut last_logged_tip, &mut last_minted_height);

    for height in 1u64..=6u64 {
        let line = next_line(&mut rx);
        let count = height % 3;

        assert!(line.contains(&format!("block: {height}")));
        assert!(line.contains(&format!("txs: {count}")));

        if height == 6 {
            assert!(line.contains("minted:    >"));
        } else {
            assert!(line.contains("accepted:  <"));
        }
    }

    assert_no_line(&mut rx);
    assert_eq!(last_logged_tip, 6);
    assert_eq!(last_minted_height, None);
}
