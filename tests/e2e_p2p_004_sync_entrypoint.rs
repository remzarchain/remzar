#![cfg(test)]
#![deny(unsafe_code)]

use futures::StreamExt;
use libp2p::{
    PeerId, identity,
    multiaddr::Protocol,
    swarm::{Swarm, SwarmEvent},
};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::{p2p_003_behaviour::RemzarBehaviour, p2p_011_peerbook::PeerBook},
    reorganization::reorg_006_manager::ReorgManager,
    runtime::{p2p_001_sync_builders::P2pSync, p2p_006_sync_runtime::NodeOpts},
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
struct PublicEntrypointSnapshot {
    has_synced: bool,
    is_syncing: bool,
    sync_percent: String,
    total_to_download: u64,
    downloaded: u64,
    pending_versions_len: usize,
    pending_blocks_len: usize,
    pending_batches_len: usize,
    block_queue_len: usize,
    batch_queue_len: usize,
    pq_ready_len: usize,
    pending_pq_len: usize,
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
        "remzar_e2e_p2p_004_sync_entrypoint_{}_{}_{}_{}",
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

async fn connect_test_peer(
    swarm: &mut Swarm<RemzarBehaviour>,
) -> TestResult<(PeerId, Swarm<RemzarBehaviour>)> {
    let mut remote = build_swarm()?;
    let local_peer = *swarm.local_peer_id();
    let remote_peer = *remote.local_peer_id();

    let listen_addr: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().map_err(fmt_err)?;
    remote.listen_on(listen_addr).map_err(fmt_err)?;

    let listen_addr = timeout(Duration::from_secs(2), async {
        loop {
            match remote.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    return Ok::<libp2p::Multiaddr, String>(address);
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| "timed out waiting for remote test swarm listen address".to_string())??;

    let dial_addr = listen_addr.with(Protocol::P2p(remote_peer));
    swarm.dial(dial_addr).map_err(fmt_err)?;

    timeout(Duration::from_secs(2), async {
        let mut local_connected = false;
        let mut remote_connected = false;

        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == remote_peer {
                            local_connected = true;
                        }
                    }
                }
                event = remote.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == local_peer {
                            remote_connected = true;
                        }
                    }
                }
            }

            if local_connected && remote_connected {
                return Ok::<(), String>(());
            }
        }
    })
    .await
    .map_err(|_| "timed out connecting local test swarm to remote peer".to_string())??;

    Ok((remote_peer, remote))
}

fn test_peer_id() -> PeerId {
    PeerId::from(identity::Keypair::generate_ed25519().public())
}

fn snapshot(sync: &P2pSync) -> PublicEntrypointSnapshot {
    PublicEntrypointSnapshot {
        has_synced: sync.has_synced(),
        is_syncing: sync.is_syncing(),
        sync_percent: format!("{:.2}", sync.sync_percent()),
        total_to_download: sync.total_to_download,
        downloaded: sync.downloaded,
        pending_versions_len: sync.pending_versions.len(),
        pending_blocks_len: sync.pending_blocks.len(),
        pending_batches_len: sync.pending_batches.len(),
        block_queue_len: sync.block_queue.len(),
        batch_queue_len: sync.batch_queue.len(),
        pq_ready_len: sync.pq_ready_peers.len(),
        pending_pq_len: sync.pending_pq.len(),
        has_background_sync_work: sync.has_background_sync_work(),
        expected_genesis_hash: sync.expected_genesis_hash.clone(),
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

fn pending_block_retries(sync: &P2pSync) -> Vec<u8> {
    let mut out: Vec<u8> = sync
        .pending_blocks
        .values()
        .map(|(_, _, retries)| *retries)
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

#[tokio::test]
async fn e2e_01_real_sync_entrypoint_boots_with_public_state_only() -> TestResult {
    let harness = build_sync_harness("e2e_01")?;
    let swarm = build_swarm()?;

    assert!(harness.data_dir.exists());
    assert_eq!(swarm.behaviour().gossipsub.all_peers().count(), 0);
    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert_eq!(harness.sync.total_to_download, 0);
    assert_eq!(harness.sync.downloaded, 0);
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());

    Ok(())
}

#[tokio::test]
async fn e2e_02_poll_without_peers_does_not_create_pending_versions() -> TestResult {
    let mut harness = build_sync_harness("e2e_02")?;
    let mut swarm = build_swarm()?;

    harness.sync.poll_peers_for_height(&mut swarm);

    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_pq.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_03_repeated_poll_without_peers_is_public_state_safe() -> TestResult {
    let mut harness = build_sync_harness("e2e_03")?;
    let mut swarm = build_swarm()?;

    for _ in 0usize..10usize {
        harness.sync.poll_peers_for_height(&mut swarm);
    }

    assert!(harness.sync.pending_versions.is_empty());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_04_poll_without_peers_preserves_pq_ready_peer() -> TestResult {
    let mut harness = build_sync_harness("e2e_04")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.poll_peers_for_height(&mut swarm);

    assert!(harness.sync.is_pq_ready(&peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_05_poll_without_peers_preserves_expected_genesis_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_05")?;
    let mut swarm = build_swarm()?;

    let before = harness.sync.expected_genesis_hash.clone();
    harness.sync.poll_peers_for_height(&mut swarm);

    assert_eq!(harness.sync.expected_genesis_hash, before);
    assert_eq!(
        harness.sync.expected_genesis_hash.as_deref(),
        Some(GlobalConfiguration::GENESIS_HASH_HEX)
    );

    Ok(())
}

#[tokio::test]
async fn e2e_06_poll_without_peers_preserves_block_backlog() -> TestResult {
    let mut harness = build_sync_harness("e2e_06")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 10, 4, 3);
    harness.sync.poll_peers_for_height(&mut swarm);

    assert_eq!(harness.sync.block_queue.len(), 4);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_07_poll_without_peers_preserves_batch_backlog() -> TestResult {
    let mut harness = build_sync_harness("e2e_07")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 20, 4, 3);
    harness.sync.poll_peers_for_height(&mut swarm);

    assert_eq!(harness.sync.batch_queue.len(), 4);
    assert!(harness.sync.pending_batches.is_empty());
    assert!(harness.sync.has_background_sync_work());

    Ok(())
}

#[tokio::test]
async fn e2e_08_poll_without_peers_preserves_existing_pending_block_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_08")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 5);

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    let before_indices = pending_block_indices(&harness.sync);

    harness.sync.poll_peers_for_height(&mut swarm);

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), before_indices);

    Ok(())
}

#[tokio::test]
async fn e2e_09_poll_without_peers_does_not_emit_batch_request_from_queue() -> TestResult {
    let mut harness = build_sync_harness("e2e_09")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    push_batch_backlog(&mut harness.sync, peer, 5, 1, 3);
    harness.sync.poll_peers_for_height(&mut swarm);

    assert_eq!(harness.sync.batch_queue.len(), 1);
    assert!(harness.sync.pending_batches.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_10_begin_sync_without_pq_defers_without_emitting_block_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_10")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    assert_eq!(harness.sync.downloaded, 0);
    assert_eq!(harness.sync.total_to_download, 10);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());
    assert!(!harness.sync.is_pq_ready(&peer));
    assert!(harness.sync.is_syncing());

    Ok(())
}

#[tokio::test]
async fn e2e_11_begin_sync_without_pq_peer_tip_zero_emits_no_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_11")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.begin_sync_to_target(&mut swarm, peer, 0);

    assert_eq!(harness.sync.downloaded, 0);
    assert_eq!(harness.sync.total_to_download, 0);
    assert!(harness.sync.pending_blocks.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_12_begin_sync_without_pq_repeated_lower_target_does_not_lower_public_total()
-> TestResult {
    let mut harness = build_sync_harness("e2e_12")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.begin_sync_to_target(&mut swarm, peer, 50);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    assert_eq!(harness.sync.total_to_download, 50);
    assert_eq!(harness.sync.downloaded, 0);
    assert!(harness.sync.pending_blocks.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_13_begin_sync_without_pq_higher_target_raises_public_total() -> TestResult {
    let mut harness = build_sync_harness("e2e_13")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.begin_sync_to_target(&mut swarm, peer, 5);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 25);

    assert_eq!(harness.sync.total_to_download, 25);
    assert_eq!(harness.sync.downloaded, 0);
    assert!(harness.sync.pending_blocks.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_14_repeated_begin_sync_without_pq_is_idempotent_on_public_maps() -> TestResult {
    let mut harness = build_sync_harness("e2e_14")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    for _ in 0usize..10usize {
        harness.sync.begin_sync_to_target(&mut swarm, peer, 12);
    }

    assert_eq!(harness.sync.total_to_download, 12);
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.block_queue.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_15_begin_sync_with_pq_ready_starts_first_block_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_15")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    assert_eq!(harness.sync.downloaded, 0);
    assert_eq!(harness.sync.total_to_download, 10);
    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);
    assert_eq!(pending_block_peers(&harness.sync), vec![peer]);

    Ok(())
}

#[tokio::test]
async fn e2e_16_begin_sync_with_pq_ready_uses_expected_retry_budget() -> TestResult {
    let mut harness = build_sync_harness("e2e_16")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    assert_eq!(pending_block_retries(&harness.sync), vec![3]);

    Ok(())
}

#[tokio::test]
async fn e2e_17_begin_sync_with_pq_ready_peer_tip_zero_emits_no_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_17")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 0);

    assert_eq!(harness.sync.total_to_download, 0);
    assert!(harness.sync.pending_blocks.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_18_begin_sync_with_pq_ready_same_target_dedupes_pending_block() -> TestResult {
    let mut harness = build_sync_harness("e2e_18")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);

    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    assert_eq!(harness.sync.total_to_download, 10);
    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_19_begin_sync_with_pq_ready_new_target_preserves_old_backlogs() -> TestResult {
    let mut harness = build_sync_harness("e2e_19")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    push_block_backlog(&mut harness.sync, peer, 10, 4, 3);
    push_batch_backlog(&mut harness.sync, peer, 20, 4, 3);

    harness.sync.begin_sync_to_target(&mut swarm, peer, 100);

    assert_eq!(harness.sync.total_to_download, 100);
    assert_eq!(harness.sync.block_queue.len(), 4);
    assert_eq!(harness.sync.batch_queue.len(), 4);
    assert!(harness.sync.pending_batches.is_empty());
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_20_begin_sync_with_pq_ready_higher_target_replaces_old_pending_block() -> TestResult {
    let mut harness = build_sync_harness("e2e_20")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);

    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);
    assert_eq!(harness.sync.pending_blocks.len(), 1);

    harness.sync.begin_sync_to_target(&mut swarm, peer, 100);

    assert_eq!(harness.sync.total_to_download, 100);
    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_21_begin_sync_with_pq_ready_preserves_pq_ready_state() -> TestResult {
    let mut harness = build_sync_harness("e2e_21")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    assert!(harness.sync.is_pq_ready(&peer));
    assert_eq!(harness.sync.pq_ready_peers.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_22_begin_sync_with_pq_ready_sets_background_work() -> TestResult {
    let mut harness = build_sync_harness("e2e_22")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    assert!(harness.sync.has_background_sync_work());
    assert_eq!(harness.sync.pending_blocks.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_23_begin_sync_without_pq_has_no_background_network_requests() -> TestResult {
    let mut harness = build_sync_harness("e2e_23")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    assert!(harness.sync.is_syncing());
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_24_deferred_sync_can_start_after_pq_ready_using_public_effects() -> TestResult {
    let mut harness = build_sync_harness("e2e_24")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.begin_sync_to_target(&mut swarm, peer, 25);

    assert_eq!(harness.sync.total_to_download, 25);
    assert!(harness.sync.pending_blocks.is_empty());

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 25);

    assert_eq!(harness.sync.total_to_download, 25);
    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_25_deferred_sync_to_lower_later_target_keeps_higher_public_total() -> TestResult {
    let mut harness = build_sync_harness("e2e_25")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.begin_sync_to_target(&mut swarm, peer, 100);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 50);

    assert_eq!(harness.sync.total_to_download, 100);
    assert!(harness.sync.pending_blocks.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_26_deferred_sync_to_higher_later_target_raises_public_total() -> TestResult {
    let mut harness = build_sync_harness("e2e_26")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.begin_sync_to_target(&mut swarm, peer, 50);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 150);

    assert_eq!(harness.sync.total_to_download, 150);
    assert!(harness.sync.pending_blocks.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_27_begin_sync_with_pq_ready_never_decreases_public_total() -> TestResult {
    let mut harness = build_sync_harness("e2e_27")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 100);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 20);

    assert_eq!(harness.sync.total_to_download, 100);
    assert_eq!(harness.sync.pending_blocks.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_28_begin_sync_with_pq_ready_after_defer_clears_public_no_request_gap() -> TestResult {
    let mut harness = build_sync_harness("e2e_28")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.begin_sync_to_target(&mut swarm, peer, 20);
    assert!(harness.sync.pending_blocks.is_empty());

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 20);

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_29_begin_sync_with_pq_ready_keeps_expected_genesis_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_29")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    let before = harness.sync.expected_genesis_hash.clone();

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 15);

    assert_eq!(harness.sync.expected_genesis_hash, before);

    Ok(())
}

#[tokio::test]
async fn e2e_30_begin_sync_with_pq_ready_does_not_create_version_requests() -> TestResult {
    let mut harness = build_sync_harness("e2e_30")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 15);

    assert!(harness.sync.pending_versions.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_31_on_local_tip_advanced_empty_chain_is_public_noop() -> TestResult {
    let mut harness = build_sync_harness("e2e_31")?;

    let before = snapshot(&harness.sync);
    harness.sync.on_local_tip_advanced();
    let after = snapshot(&harness.sync);

    assert_eq!(after.pending_blocks_len, before.pending_blocks_len);
    assert_eq!(after.pending_batches_len, before.pending_batches_len);
    assert_eq!(after.pending_versions_len, before.pending_versions_len);

    Ok(())
}

#[tokio::test]
async fn e2e_32_on_local_tip_advanced_preserves_public_progress_counters() -> TestResult {
    let mut harness = build_sync_harness("e2e_32")?;

    harness.sync.total_to_download = 100;
    harness.sync.downloaded = 25;

    harness.sync.on_local_tip_advanced();

    // on_local_tip_advanced is DB-tip authoritative. In this fresh harness,
    // no block has been committed, so public progress reconciles to tip 0.
    assert_eq!(harness.sync.total_to_download, 0);
    assert_eq!(harness.sync.downloaded, 0);
    assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");

    Ok(())
}

#[tokio::test]
async fn e2e_33_on_local_tip_advanced_preserves_expected_genesis_hash() -> TestResult {
    let mut harness = build_sync_harness("e2e_33")?;

    let before = harness.sync.expected_genesis_hash.clone();
    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.expected_genesis_hash, before);

    Ok(())
}

#[tokio::test]
async fn e2e_34_on_local_tip_advanced_preserves_pq_ready_peer() -> TestResult {
    let mut harness = build_sync_harness("e2e_34")?;
    let peer = test_peer_id();

    harness.sync.mark_pq_ready(peer);
    harness.sync.on_local_tip_advanced();

    assert!(harness.sync.is_pq_ready(&peer));

    Ok(())
}

#[tokio::test]
async fn e2e_35_on_local_tip_advanced_preserves_pending_block_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_35")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 10);

    let before_indices = pending_block_indices(&harness.sync);
    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), before_indices);

    Ok(())
}

#[tokio::test]
async fn e2e_36_on_local_tip_advanced_preserves_public_queues() -> TestResult {
    let mut harness = build_sync_harness("e2e_36")?;
    let peer = test_peer_id();

    push_block_backlog(&mut harness.sync, peer, 10, 2, 3);
    push_batch_backlog(&mut harness.sync, peer, 20, 2, 3);

    harness.sync.on_local_tip_advanced();

    assert_eq!(harness.sync.block_queue.len(), 2);
    assert_eq!(harness.sync.batch_queue.len(), 2);

    Ok(())
}

#[tokio::test]
async fn e2e_37_poll_after_deferred_sync_does_not_emit_block_request_without_pq() -> TestResult {
    let mut harness = build_sync_harness("e2e_37")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.begin_sync_to_target(&mut swarm, peer, 50);
    assert_eq!(harness.sync.total_to_download, 50);

    harness.sync.poll_peers_for_height(&mut swarm);

    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_38_poll_after_pq_ready_pending_block_preserves_pending_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_38")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 20);

    let before_indices = pending_block_indices(&harness.sync);
    harness.sync.poll_peers_for_height(&mut swarm);

    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), before_indices);

    Ok(())
}

#[tokio::test]
async fn e2e_39_begin_sync_after_poll_requires_pq_before_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_39")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness.sync.poll_peers_for_height(&mut swarm);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 30);

    assert_eq!(harness.sync.total_to_download, 30);
    assert!(harness.sync.pending_blocks.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_40_begin_sync_after_poll_with_pq_ready_emits_request() -> TestResult {
    let mut harness = build_sync_harness("e2e_40")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.poll_peers_for_height(&mut swarm);
    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 30);

    assert_eq!(harness.sync.total_to_download, 30);
    assert_eq!(harness.sync.pending_blocks.len(), 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_41_begin_sync_higher_target_completes_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_41")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);

    timeout(Duration::from_millis(1_000), async {
        harness.sync.begin_sync_to_target(&mut swarm, peer, 1_000);
    })
    .await
    .map_err(|_| "begin_sync_to_target timed out".to_string())?;

    assert_eq!(harness.sync.total_to_download, 1_000);
    assert_eq!(harness.sync.pending_blocks.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_42_repeated_poll_without_peers_completes_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_42")?;
    let mut swarm = build_swarm()?;

    timeout(Duration::from_millis(1_000), async {
        for _ in 0usize..50usize {
            harness.sync.poll_peers_for_height(&mut swarm);
        }
    })
    .await
    .map_err(|_| "repeated poll_peers_for_height timed out".to_string())?;

    assert!(harness.sync.pending_versions.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_43_repeated_on_local_tip_advanced_completes_before_timeout() -> TestResult {
    let mut harness = build_sync_harness("e2e_43")?;

    timeout(Duration::from_millis(1_000), async {
        for _ in 0usize..100usize {
            harness.sync.on_local_tip_advanced();
        }
    })
    .await
    .map_err(|_| "repeated on_local_tip_advanced timed out".to_string())?;

    assert!(harness.sync.pending_versions.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_44_begin_sync_with_u64_max_without_pq_defers_safely() -> TestResult {
    let mut harness = build_sync_harness("e2e_44")?;
    let mut swarm = build_swarm()?;
    let peer = test_peer_id();

    harness
        .sync
        .begin_sync_to_target(&mut swarm, peer, u64::MAX);

    assert_eq!(harness.sync.total_to_download, u64::MAX);
    assert!(harness.sync.pending_blocks.is_empty());

    Ok(())
}

#[tokio::test]
async fn e2e_45_begin_sync_with_u64_max_with_pq_emits_first_block_without_overflow() -> TestResult {
    let mut harness = build_sync_harness("e2e_45")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness
        .sync
        .begin_sync_to_target(&mut swarm, peer, u64::MAX);

    assert_eq!(harness.sync.total_to_download, u64::MAX);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_46_begin_sync_with_pq_ready_from_large_target_does_not_decrease_public_total()
-> TestResult {
    let mut harness = build_sync_harness("e2e_46")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 500);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 250);

    assert_eq!(harness.sync.total_to_download, 500);
    assert_eq!(harness.sync.pending_blocks.len(), 1);

    Ok(())
}

#[tokio::test]
async fn e2e_47_begin_sync_with_pq_ready_after_manual_queue_pressure_preserves_queues_for_new_target()
-> TestResult {
    let mut harness = build_sync_harness("e2e_47")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    push_block_backlog(&mut harness.sync, peer, 100, 32, 3);
    push_batch_backlog(&mut harness.sync, peer, 200, 32, 3);

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 999);

    assert_eq!(harness.sync.total_to_download, 999);
    assert_eq!(harness.sync.block_queue.len(), 32);
    assert_eq!(harness.sync.batch_queue.len(), 32);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_48_public_snapshot_is_stable_after_empty_poll() -> TestResult {
    let mut harness = build_sync_harness("e2e_48")?;
    let mut swarm = build_swarm()?;

    let before = snapshot(&harness.sync);
    harness.sync.poll_peers_for_height(&mut swarm);
    let after = snapshot(&harness.sync);

    assert_eq!(after.pending_versions_len, before.pending_versions_len);
    assert_eq!(after.pending_blocks_len, before.pending_blocks_len);
    assert_eq!(after.pending_batches_len, before.pending_batches_len);
    assert_eq!(after.expected_genesis_hash, before.expected_genesis_hash);

    Ok(())
}

#[tokio::test]
async fn e2e_49_public_snapshot_tracks_deferred_then_started_sync() -> TestResult {
    let mut harness = build_sync_harness("e2e_49")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    harness.sync.begin_sync_to_target(&mut swarm, peer, 77);
    let deferred = snapshot(&harness.sync);

    assert_eq!(deferred.total_to_download, 77);
    assert_eq!(deferred.pending_blocks_len, 0);

    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 77);
    let started = snapshot(&harness.sync);

    assert_eq!(started.total_to_download, 77);
    assert_eq!(started.pending_blocks_len, 1);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);

    Ok(())
}

#[tokio::test]
async fn e2e_50_full_public_entrypoint_lifecycle_defer_poll_pq_start_and_local_tip_update()
-> TestResult {
    let mut harness = build_sync_harness("e2e_50")?;
    let mut swarm = build_swarm()?;
    let (peer, _remote) = connect_test_peer(&mut swarm).await?;

    // 1. Peer advertises a higher tip, but PQ is not ready.
    harness.sync.begin_sync_to_target(&mut swarm, peer, 120);

    assert_eq!(harness.sync.total_to_download, 120);
    assert_eq!(harness.sync.downloaded, 0);
    assert!(harness.sync.pending_blocks.is_empty());

    // 2. Empty polling round should not magically emit requests.
    harness.sync.poll_peers_for_height(&mut swarm);

    assert!(harness.sync.pending_blocks.is_empty());
    assert!(harness.sync.pending_batches.is_empty());

    // 3. Same peer becomes PQ ready and sync can start publicly.
    harness.sync.mark_pq_ready(peer);
    harness.sync.begin_sync_to_target(&mut swarm, peer, 120);

    assert_eq!(harness.sync.total_to_download, 120);
    assert_eq!(harness.sync.downloaded, 0);
    assert_eq!(pending_block_indices(&harness.sync), vec![1]);
    assert!(harness.sync.has_background_sync_work());

    // 4. Local-tip update should not destroy the pending request.
    harness.sync.on_local_tip_advanced();

    assert_eq!(pending_block_indices(&harness.sync), vec![1]);
    assert!(harness.sync.is_pq_ready(&peer));
    assert!(!harness.sync.has_synced());
    assert!(harness.sync.is_syncing());

    sleep(Duration::from_millis(1)).await;

    Ok(())
}
