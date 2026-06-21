#![cfg(test)]
#![deny(unsafe_code)]

use libp2p::{
    PeerId,
    gossipsub::{Event as GossipsubEvent, IdentTopic},
    identity,
    swarm::{Swarm, SwarmEvent},
};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::{
        p2p_003_behaviour::{OutEvent, RemzarBehaviour},
        p2p_011_peerbook::PeerBook,
    },
    reorganization::reorg_006_manager::ReorgManager,
    runtime::{
        p2p_001_sync_builders::{P2pSync, REGISTRATION_TOPIC},
        p2p_006_sync_runtime::NodeOpts,
    },
    storage::rocksdb_005_manager::RockDBManager,
    utility::{
        alpha_001_global_configuration::GlobalConfiguration,
        alpha_003_detection_system::DetectionSystem,
    },
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{sleep, timeout};

type TestResult<T = ()> = Result<T, String>;

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct SyncHarness {
    sync: P2pSync,
    data_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicSwarmSyncSnapshot {
    has_synced: bool,
    is_syncing: bool,
    sync_percent: String,
    total_to_download: u64,
    downloaded: u64,
    block_queue_len: usize,
    batch_queue_len: usize,
    pending_blocks_len: usize,
    pending_batches_len: usize,
    pending_pq_len: usize,
    pq_ready_len: usize,
    has_background_sync_work: bool,
    expected_genesis_hash: Option<String>,
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn now_millis_for_test() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}

fn unique_data_dir(test_name: &str) -> PathBuf {
    let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "remzar_e2e_p2p_003_sync_swarmevent_{}_{}_{}_{}",
        std::process::id(),
        now_millis_for_test(),
        counter,
        test_name
    ))
}

fn build_node_opts(data_dir: &Path) -> NodeOpts {
    NodeOpts {
        identity_file: "identity.key".to_string(),
        listen: "/ip4/127.0.0.1/tcp/0".to_string(),
        bootstrap: Vec::new(),
        log: "error".to_string(),
        data_dir: data_dir.to_string_lossy().into_owned(),
        wallet_address: GlobalConfiguration::GENESIS_VALIDATOR.to_string(),
        founder: false,
    }
}

fn build_sync_harness(test_name: &str) -> TestResult<SyncHarness> {
    let data_dir = unique_data_dir(test_name);
    std::fs::create_dir_all(&data_dir).map_err(fmt_err)?;

    let opts = build_node_opts(&data_dir);
    let blockchain_path = data_dir.join(GlobalConfiguration::BLOCKCHAIN_DATABASE_DIR);
    let blockchain_path_text = blockchain_path.to_string_lossy().into_owned();

    let db = Arc::new(
        RockDBManager::new_blockchain(&opts, blockchain_path_text.as_str()).map_err(fmt_err)?,
    );

    let chain = AccountModelTree::with_manager((*db).clone());
    let detection = Arc::new(DetectionSystem::new());
    let mempool = Arc::new(MemPool::new(Arc::clone(&db), detection));
    let peerbook = Arc::new(Mutex::new(PeerBook::default()));
    let reorg_manager = ReorgManager::mainnet_default(Arc::clone(&db));

    let sync = P2pSync::new(
        chain,
        Arc::clone(&db),
        mempool,
        peerbook,
        data_dir.join(GlobalConfiguration::PEER_LIST_DIR),
        Some(GlobalConfiguration::GENESIS_HASH_HEX.to_string()),
        reorg_manager,
    );

    Ok(SyncHarness { sync, data_dir })
}

fn build_swarm() -> TestResult<Swarm<RemzarBehaviour>> {
    let keypair = identity::Keypair::generate_ed25519();

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(fmt_err)?
        .with_behaviour(|key| {
            RemzarBehaviour::new(key.clone()).unwrap_or_else(|err| {
                panic!("failed to build RemzarBehaviour for e2e test swarm: {err}");
            })
        })
        .map_err(fmt_err)?
        .build();

    Ok(swarm)
}

fn test_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn snapshot(sync: &P2pSync) -> PublicSwarmSyncSnapshot {
    PublicSwarmSyncSnapshot {
        has_synced: sync.has_synced(),
        is_syncing: sync.is_syncing(),
        sync_percent: format!("{:.2}", sync.sync_percent()),
        total_to_download: sync.total_to_download,
        downloaded: sync.downloaded,
        block_queue_len: sync.block_queue.len(),
        batch_queue_len: sync.batch_queue.len(),
        pending_blocks_len: sync.pending_blocks.len(),
        pending_batches_len: sync.pending_batches.len(),
        pending_pq_len: sync.pending_pq.len(),
        pq_ready_len: sync.pq_ready_peers.len(),
        has_background_sync_work: sync.has_background_sync_work(),
        expected_genesis_hash: sync.expected_genesis_hash.clone(),
    }
}

fn gossip_subscribed_event(peer: PeerId, topic: &str) -> SwarmEvent<OutEvent> {
    let topic = IdentTopic::new(topic);
    SwarmEvent::Behaviour(OutEvent::Gossip(Box::new(GossipsubEvent::Subscribed {
        peer_id: peer,
        topic: topic.hash(),
    })))
}

fn gossip_unsubscribed_event(peer: PeerId, topic: &str) -> SwarmEvent<OutEvent> {
    let topic = IdentTopic::new(topic);
    SwarmEvent::Behaviour(OutEvent::Gossip(Box::new(GossipsubEvent::Unsubscribed {
        peer_id: peer,
        topic: topic.hash(),
    })))
}

fn drive_gossip_tick(sync: &mut P2pSync, swarm: &mut Swarm<RemzarBehaviour>) {
    let peer = test_peer_id();
    sync.on_swarm_event(
        gossip_subscribed_event(peer, REGISTRATION_TOPIC),
        swarm,
        None,
    );
}

fn drive_gossip_unsub_tick(sync: &mut P2pSync, swarm: &mut Swarm<RemzarBehaviour>) {
    let peer = test_peer_id();
    sync.on_swarm_event(
        gossip_unsubscribed_event(peer, REGISTRATION_TOPIC),
        swarm,
        None,
    );
}

fn push_block_backlog(sync: &mut P2pSync, peer: PeerId, start: u64, count: u64, retries: u8) {
    for offset in 0..count {
        sync.block_queue
            .push_back((peer, start.saturating_add(offset), retries));
    }
}

fn push_batch_backlog(sync: &mut P2pSync, peer: PeerId, start: u64, count: u64, retries: u8) {
    for offset in 0..count {
        sync.batch_queue
            .push_back((peer, start.saturating_add(offset), retries));
    }
}

fn pending_block_indices(sync: &P2pSync) -> Vec<u64> {
    let mut out: Vec<u64> = sync
        .pending_blocks
        .values()
        .map(|(_, idx, _)| *idx)
        .collect();
    out.sort_unstable();
    out
}

fn pending_batch_indices(sync: &P2pSync) -> Vec<u64> {
    let mut out: Vec<u64> = sync.pending_batches.values().map(|req| req.idx).collect();
    out.sort_unstable();
    out
}

fn pending_block_retries(sync: &P2pSync) -> Vec<u8> {
    let mut out: Vec<u8> = sync
        .pending_blocks
        .values()
        .map(|(_, _, retries)| *retries)
        .collect();
    out.sort_unstable();
    out
}

fn pending_batch_retries(sync: &P2pSync) -> Vec<u8> {
    let mut out: Vec<u8> = sync
        .pending_batches
        .values()
        .map(|req| req.retries_left)
        .collect();
    out.sort_unstable();
    out
}

fn pending_block_peers(sync: &P2pSync) -> Vec<PeerId> {
    let mut out: Vec<PeerId> = sync
        .pending_blocks
        .values()
        .map(|(peer, _, _)| *peer)
        .collect();
    out.sort_by_key(|peer| peer.to_string());
    out
}

fn pending_batch_peers(sync: &P2pSync) -> Vec<PeerId> {
    let mut out: Vec<PeerId> = sync.pending_batches.values().map(|req| req.peer).collect();
    out.sort_by_key(|peer| peer.to_string());
    out
}

#[tokio::test]
async fn e2e_01_real_sync_and_real_swarm_boot_for_swarmevent_tests() -> TestResult {
    let harness = build_sync_harness("e2e_01")?;
    let swarm = build_swarm()?;

    assert!(harness.data_dir.exists());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());
    assert_eq!(swarm.behaviour().gossipsub.all_peers().count(), 0);

    Ok(())
}

#[tokio::test]
async fn e2e_02_gossip_subscribed_event_with_empty_queues_is_noop_for_public_state() -> TestResult {
    let mut harness = build_sync_harness("e2e_02")?;
    let mut swarm = build_swarm()?;

    let before = snapshot(&harness.sync);
    drive_gossip_tick(&mut harness.sync, &mut swarm);
    let after = snapshot(&harness.sync);

    assert_eq!(after, before);
    Ok(())
}

#[tokio::test]
async fn e2e_03_gossip_unsubscribed_event_with_empty_queues_is_noop_for_public_state() -> TestResult
{
    let mut harness = build_sync_harness("e2e_03")?;
    let mut swarm = build_swarm()?;

    let before = snapshot(&harness.sync);
    drive_gossip_unsub_tick(&mut harness.sync, &mut swarm);
    let after = snapshot(&harness.sync);

    assert_eq!(after, before);
    Ok(())
}

#[tokio::test]
async fn e2e_04_gossip_event_preserves_pq_ready_peer() -> TestResult {
    let mut harness = build_sync_harness("e2e_04")?;
    let mut swarm = build_swarm()?;
    let ready_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1);
    Ok(())
}

#[tokio::test]
async fn e2e_05_single_block_queue_item_becomes_pending_block_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_05")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 1, 1, 3);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.block_queue.is_empty());
    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);
    assert_eq!(pending_block_retries(&harness.sync), vec![3]);

    Ok(())
}

#[tokio::test]
async fn e2e_06_single_block_queue_item_preserves_origin_peer() -> TestResult {
    let mut harness = build_sync_harness("e2e_06")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 7, 1, 2);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_peers(&harness.sync), vec![peer]);
    assert_eq!(pending_block_indices(&harness.sync), vec![7]);
    assert_eq!(pending_block_retries(&harness.sync), vec![2]);

    Ok(())
}

#[tokio::test]
async fn e2e_07_block_queue_issues_only_first_item_per_tick() -> TestResult {
    let mut harness = build_sync_harness("e2e_07")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 10, 3, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![10]);
    assert_eq!(harness.sync.block_queue.len(), 2);

    Ok(())
}

#[tokio::test]
async fn e2e_08_existing_pending_block_prevents_new_block_issue() -> TestResult {
    let mut harness = build_sync_harness("e2e_08")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 20, 2, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    let pending_after_first = harness.sync.pending_blocks.len();
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_after_first, 1);
    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(harness.sync.block_queue.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_09_next_block_queue_item_issues_after_pending_blocks_clear() -> TestResult {
    let mut harness = build_sync_harness("e2e_09")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 30, 2, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![30]);

    harness.sync.pending_blocks.clear();
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![31]);
    assert!(harness.sync.block_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_10_duplicate_block_index_is_deduped_after_first_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_10")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, 40, 3));
    harness.sync.block_queue.push_back((peer, 40, 3));

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![40]);
    assert!(harness.sync.block_queue.is_empty());

    let pending_len_after_first = harness.sync.pending_blocks.len();

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    // Existing pending request prevents duplicate re-issue.
    assert_eq!(harness.sync.pending_blocks.len(), pending_len_after_first);
    assert_eq!(pending_block_indices(&harness.sync), vec![40]);
    assert!(harness.sync.block_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_11_single_batch_queue_item_becomes_pending_batch_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_11")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 1, 1, 3);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.batch_queue.is_empty());
    assert_eq!(harness.sync.pending_batches.len(), 1);
    assert_eq!(pending_batch_indices(&harness.sync), vec![1]);
    assert_eq!(pending_batch_retries(&harness.sync), vec![3]);

    Ok(())
}

#[tokio::test]
async fn e2e_12_single_batch_queue_item_preserves_origin_peer() -> TestResult {
    let mut harness = build_sync_harness("e2e_12")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 8, 1, 2);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_batch_peers(&harness.sync), vec![peer]);
    assert_eq!(pending_batch_indices(&harness.sync), vec![8]);
    assert_eq!(pending_batch_retries(&harness.sync), vec![2]);

    Ok(())
}

#[tokio::test]
async fn e2e_13_batch_index_zero_is_skipped_because_applied_height_is_zero() -> TestResult {
    let mut harness = build_sync_harness("e2e_13")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 0, 1, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.batch_queue.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_14_batch_queue_issues_only_first_item_per_tick() -> TestResult {
    let mut harness = build_sync_harness("e2e_14")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 50, 3, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.pending_batches.len(), 1);
    assert_eq!(pending_batch_indices(&harness.sync), vec![50]);
    assert_eq!(harness.sync.batch_queue.len(), 2);

    Ok(())
}

#[tokio::test]
async fn e2e_15_existing_pending_batch_prevents_new_batch_issue() -> TestResult {
    let mut harness = build_sync_harness("e2e_15")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 60, 2, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    let pending_after_first = harness.sync.pending_batches.len();
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_after_first, 1);
    assert_eq!(harness.sync.pending_batches.len(), 1);
    assert_eq!(harness.sync.batch_queue.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_16_next_batch_queue_item_issues_after_pending_batches_clear() -> TestResult {
    let mut harness = build_sync_harness("e2e_16")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 70, 2, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_batch_indices(&harness.sync), vec![70]);

    harness.sync.pending_batches.clear();
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_batch_indices(&harness.sync), vec![71]);
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_17_duplicate_batch_index_is_deduped_after_first_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_17")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 80, 3));
    harness.sync.batch_queue.push_back((peer, 80, 3));

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_batch_indices(&harness.sync), vec![80]);
    assert!(harness.sync.batch_queue.is_empty());

    let pending_len_after_first = harness.sync.pending_batches.len();

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    // Existing pending request prevents duplicate re-issue.
    assert_eq!(harness.sync.pending_batches.len(), pending_len_after_first);
    assert_eq!(pending_batch_indices(&harness.sync), vec![80]);
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_18_block_and_batch_queues_can_both_issue_in_one_tick() -> TestResult {
    let mut harness = build_sync_harness("e2e_18")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 90, 1, 3);
    push_batch_backlog(&mut harness.sync, peer, 91, 1, 2);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![90]);
    assert_eq!(pending_batch_indices(&harness.sync), vec![91]);
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_19_genesis_block_queue_index_zero_issues_block_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_19")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 0, 1, 3);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![0]);
    assert!(harness.sync.block_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_20_batch_index_zero_skips_but_block_index_zero_still_issues() -> TestResult {
    let mut harness = build_sync_harness("e2e_20")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 0, 1, 3);
    push_batch_backlog(&mut harness.sync, peer, 0, 1, 3);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![0]);
    assert!(harness.sync.pending_batches.is_empty());
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_21_many_block_items_issue_one_by_one_when_pending_is_cleared() -> TestResult {
    let mut harness = build_sync_harness("e2e_21")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 100, 5, 3);

    for expected in 100u64..105u64 {
        drive_gossip_tick(&mut harness.sync, &mut swarm);
        assert_eq!(pending_block_indices(&harness.sync), vec![expected]);
        harness.sync.pending_blocks.clear();
    }

    assert!(harness.sync.block_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_22_many_batch_items_issue_one_by_one_when_pending_is_cleared() -> TestResult {
    let mut harness = build_sync_harness("e2e_22")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 200, 5, 2);

    for expected in 200u64..205u64 {
        drive_gossip_tick(&mut harness.sync, &mut swarm);
        assert_eq!(pending_batch_indices(&harness.sync), vec![expected]);
        harness.sync.pending_batches.clear();
    }

    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_23_mixed_queues_issue_one_each_per_tick_when_pending_maps_are_cleared() -> TestResult {
    let mut harness = build_sync_harness("e2e_23")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 300, 3, 3);
    push_batch_backlog(&mut harness.sync, peer, 400, 3, 2);

    for step in 0u64..3u64 {
        drive_gossip_tick(&mut harness.sync, &mut swarm);

        assert_eq!(pending_block_indices(&harness.sync), vec![300 + step]);
        assert_eq!(pending_batch_indices(&harness.sync), vec![400 + step]);

        harness.sync.pending_blocks.clear();
        harness.sync.pending_batches.clear();
    }

    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_24_existing_pending_block_does_not_prevent_batch_queue_issue() -> TestResult {
    let mut harness = build_sync_harness("e2e_24")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 500, 2, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    push_batch_backlog(&mut harness.sync, peer, 600, 1, 2);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(harness.sync.pending_batches.len(), 1);
    assert_eq!(pending_batch_indices(&harness.sync), vec![600]);

    Ok(())
}

#[tokio::test]
async fn e2e_25_existing_pending_batch_does_not_prevent_block_queue_issue() -> TestResult {
    let mut harness = build_sync_harness("e2e_25")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 700, 2, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    push_block_backlog(&mut harness.sync, peer, 800, 1, 2);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.pending_batches.len(), 1);
    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![800]);

    Ok(())
}

#[tokio::test]
async fn e2e_26_two_peer_block_queue_preserves_first_peer_fifo() -> TestResult {
    let mut harness = build_sync_harness("e2e_26")?;
    let mut swarm = build_swarm()?;
    let first = test_peer_id();
    let second = test_peer_id();

    harness.sync.block_queue.push_back((first, 900, 3));
    harness.sync.block_queue.push_back((second, 901, 3));

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_peers(&harness.sync), vec![first]);
    assert_eq!(pending_block_indices(&harness.sync), vec![900]);
    assert_eq!(harness.sync.block_queue.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_27_two_peer_batch_queue_preserves_first_peer_fifo() -> TestResult {
    let mut harness = build_sync_harness("e2e_27")?;
    let mut swarm = build_swarm()?;
    let first = test_peer_id();
    let second = test_peer_id();

    harness.sync.batch_queue.push_back((first, 910, 3));
    harness.sync.batch_queue.push_back((second, 911, 3));

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_batch_peers(&harness.sync), vec![first]);
    assert_eq!(pending_batch_indices(&harness.sync), vec![910]);
    assert_eq!(harness.sync.batch_queue.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_28_block_issue_does_not_clear_existing_pq_ready_set() -> TestResult {
    let mut harness = build_sync_harness("e2e_28")?;
    let mut swarm = build_swarm()?;

    let ready_peer = test_peer_id();
    let queue_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    push_block_backlog(&mut harness.sync, queue_peer, 920, 1, 3);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![920]);

    Ok(())
}

#[tokio::test]
async fn e2e_29_batch_issue_does_not_clear_existing_pq_ready_set() -> TestResult {
    let mut harness = build_sync_harness("e2e_29")?;
    let mut swarm = build_swarm()?;

    let ready_peer = test_peer_id();
    let queue_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    push_batch_backlog(&mut harness.sync, queue_peer, 930, 1, 3);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1);
    assert_eq!(pending_batch_indices(&harness.sync), vec![930]);

    Ok(())
}

#[tokio::test]
async fn e2e_30_gossip_event_preserves_expected_genesis_hash_configuration() -> TestResult {
    let mut harness = build_sync_harness("e2e_30")?;
    let mut swarm = build_swarm()?;

    let before = harness.sync.expected_genesis_hash.clone();
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.expected_genesis_hash, before);
    assert_eq!(
        harness.sync.expected_genesis_hash.as_deref(),
        Some(GlobalConfiguration::GENESIS_HASH_HEX)
    );

    Ok(())
}

#[tokio::test]
async fn e2e_31_sync_progress_counters_are_preserved_when_block_request_is_issued() -> TestResult {
    let mut harness = build_sync_harness("e2e_31")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.total_to_download = 100;
    harness.sync.downloaded = 25;

    push_block_backlog(&mut harness.sync, peer, 940, 1, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.total_to_download, 100);
    assert_eq!(harness.sync.downloaded, 25);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");

    Ok(())
}

#[tokio::test]
async fn e2e_32_sync_progress_counters_are_preserved_when_batch_request_is_issued() -> TestResult {
    let mut harness = build_sync_harness("e2e_32")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.total_to_download = 200;
    harness.sync.downloaded = 50;

    push_batch_backlog(&mut harness.sync, peer, 950, 1, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.total_to_download, 200);
    assert_eq!(harness.sync.downloaded, 50);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");

    Ok(())
}

#[tokio::test]
async fn e2e_33_repeated_empty_gossip_ticks_do_not_create_pending_requests() -> TestResult {
    let mut harness = build_sync_harness("e2e_33")?;
    let mut swarm = build_swarm()?;

    for _ in 0usize..25usize {
        drive_gossip_tick(&mut harness.sync, &mut swarm);
    }

    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_34_repeated_gossip_ticks_with_pending_block_do_not_duplicate_block_request()
-> TestResult {
    let mut harness = build_sync_harness("e2e_34")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 960, 2, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    for _ in 0usize..10usize {
        drive_gossip_tick(&mut harness.sync, &mut swarm);
    }

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![960]);
    assert_eq!(harness.sync.block_queue.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_35_repeated_gossip_ticks_with_pending_batch_do_not_duplicate_batch_request()
-> TestResult {
    let mut harness = build_sync_harness("e2e_35")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 970, 2, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    for _ in 0usize..10usize {
        drive_gossip_tick(&mut harness.sync, &mut swarm);
    }

    assert_eq!(harness.sync.pending_batches.len(), 1);
    assert_eq!(pending_batch_indices(&harness.sync), vec![970]);
    assert_eq!(harness.sync.batch_queue.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_36_large_block_backlog_issues_one_and_preserves_rest() -> TestResult {
    let mut harness = build_sync_harness("e2e_36")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 1_000, 128, 3);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1_000]);
    assert_eq!(harness.sync.block_queue.len(), 127);

    Ok(())
}

#[tokio::test]
async fn e2e_37_large_batch_backlog_issues_one_and_preserves_rest() -> TestResult {
    let mut harness = build_sync_harness("e2e_37")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 2_000, 128, 3);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(harness.sync.pending_batches.len(), 1);
    assert_eq!(pending_batch_indices(&harness.sync), vec![2_000]);
    assert_eq!(harness.sync.batch_queue.len(), 127);

    Ok(())
}

#[tokio::test]
async fn e2e_38_zero_retry_block_queue_item_still_issues_request_with_zero_retry_budget()
-> TestResult {
    let mut harness = build_sync_harness("e2e_38")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 3_000, 1, 0);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![3_000]);
    assert_eq!(pending_block_retries(&harness.sync), vec![0]);

    Ok(())
}

#[tokio::test]
async fn e2e_39_zero_retry_batch_queue_item_still_issues_request_with_zero_retry_budget()
-> TestResult {
    let mut harness = build_sync_harness("e2e_39")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 3_100, 1, 0);

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_batch_indices(&harness.sync), vec![3_100]);
    assert_eq!(pending_batch_retries(&harness.sync), vec![0]);

    Ok(())
}

#[tokio::test]
async fn e2e_40_u64_max_block_index_can_be_queued_and_issued_without_panic() -> TestResult {
    let mut harness = build_sync_harness("e2e_40")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.block_queue.push_back((peer, u64::MAX, 1));

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![u64::MAX]);
    assert!(harness.sync.block_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_41_u64_max_batch_index_can_be_queued_and_issued_without_panic() -> TestResult {
    let mut harness = build_sync_harness("e2e_41")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, u64::MAX, 1));

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_batch_indices(&harness.sync), vec![u64::MAX]);
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_42_large_backlog_tick_completes_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_42")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 4_000, 512, 3);
    push_batch_backlog(&mut harness.sync, peer, 5_000, 512, 3);

    timeout(Duration::from_millis(1_000), async {
        drive_gossip_tick(&mut harness.sync, &mut swarm);
    })
    .await
    .map_err(|_| "large swarmevent backlog tick timed out".to_string())?;

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(harness.sync.pending_batches.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_43_pending_block_request_counts_as_background_sync_work_after_tick() -> TestResult {
    let mut harness = build_sync_harness("e2e_43")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 6_000, 1, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.pending_blocks.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_44_pending_batch_request_counts_as_background_sync_work_after_tick() -> TestResult {
    let mut harness = build_sync_harness("e2e_44")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 6_100, 1, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.pending_batches.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_45_unsubscribed_event_also_drives_block_queue_pump() -> TestResult {
    let mut harness = build_sync_harness("e2e_45")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 6_200, 1, 3);
    drive_gossip_unsub_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![6_200]);
    assert!(harness.sync.block_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_46_unsubscribed_event_also_drives_batch_queue_pump() -> TestResult {
    let mut harness = build_sync_harness("e2e_46")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 6_300, 1, 3);
    drive_gossip_unsub_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_batch_indices(&harness.sync), vec![6_300]);
    assert!(harness.sync.batch_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_47_skipped_zero_batch_index_leaves_no_pending_or_background_work() -> TestResult {
    let mut harness = build_sync_harness("e2e_47")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.batch_queue.push_back((peer, 0, 3));
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert!(harness.sync.batch_queue.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert!(!harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_48_pending_batch_request_has_no_expected_block_hash_for_index_queue_path() -> TestResult
{
    let mut harness = build_sync_harness("e2e_48")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 6_400, 1, 3);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    let request = harness
        .sync
        .pending_batches
        .values()
        .next()
        .ok_or_else(|| "missing pending batch request".to_string())?;

    assert_eq!(request.peer, peer);
    assert_eq!(request.idx, 6_400);
    assert_eq!(request.retries_left, 3);
    assert!(request.expected_block_hash.is_none());

    Ok(())
}

#[tokio::test]
async fn e2e_49_pending_block_request_preserves_retry_budget_for_index_queue_path() -> TestResult {
    let mut harness = build_sync_harness("e2e_49")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 6_500, 1, 7);
    drive_gossip_tick(&mut harness.sync, &mut swarm);

    let (_, idx, retries_left) = harness
        .sync
        .pending_blocks
        .values()
        .next()
        .copied()
        .ok_or_else(|| "missing pending block request".to_string())?;

    assert_eq!(idx, 6_500);
    assert_eq!(retries_left, 7);

    Ok(())
}

#[tokio::test]
async fn e2e_50_full_swarmevent_queue_lifecycle_block_batch_dedup_and_progress_safety() -> TestResult
{
    let mut harness = build_sync_harness("e2e_50")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();
    let ready_peer = test_peer_id();

    harness.sync.mark_pq_ready(ready_peer);
    harness.sync.total_to_download = 10_000;
    harness.sync.downloaded = 2_500;

    harness.sync.block_queue.push_back((peer, 7_000, 3));
    harness.sync.block_queue.push_back((peer, 7_000, 3));
    harness.sync.block_queue.push_back((peer, 7_001, 2));

    harness.sync.batch_queue.push_back((peer, 8_000, 3));
    harness.sync.batch_queue.push_back((peer, 8_000, 3));
    harness.sync.batch_queue.push_back((peer, 8_001, 2));

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    assert_eq!(pending_block_indices(&harness.sync), vec![7_000]);
    assert_eq!(pending_batch_indices(&harness.sync), vec![8_000]);
    assert_eq!(harness.sync.block_queue.len(), 1);
    assert_eq!(harness.sync.batch_queue.len(), 1);

    harness.sync.pending_blocks.clear();
    harness.sync.pending_batches.clear();

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    // Second tick issues the next unique queued work.
    assert_eq!(pending_block_indices(&harness.sync), vec![7_001]);
    assert_eq!(pending_batch_indices(&harness.sync), vec![8_001]);
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());

    drive_gossip_tick(&mut harness.sync, &mut swarm);

    // Existing pending requests prevent duplicate re-issue.
    assert_eq!(pending_block_indices(&harness.sync), vec![7_001]);
    assert_eq!(pending_batch_indices(&harness.sync), vec![8_001]);
    assert!(harness.sync.block_queue.is_empty());
    assert!(harness.sync.batch_queue.is_empty());

    assert!(harness.sync.is_pq_ready(&ready_peer));
    assert_eq!(harness.sync.total_to_download, 10_000);
    assert_eq!(harness.sync.downloaded, 2_500);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
    assert!(harness.sync.has_background_sync_work());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());

    sleep(Duration::from_millis(1)).await;

    Ok(())
}
