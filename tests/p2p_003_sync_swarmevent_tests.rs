#![cfg(test)]
#![deny(unsafe_code)]

use futures::{Future, StreamExt};
use libp2p::{
    Multiaddr, PeerId, Swarm,
    gossipsub::IdentTopic,
    identity,
    swarm::{Config as SwarmConfig, SwarmEvent},
};
use remzar::{
    blockchain::{mempool::MemPool, transaction_005_tx_account_tree::AccountModelTree},
    network::{
        p2p_001_transport::build_transport,
        p2p_003_behaviour::{OutEvent, RemzarBehaviour},
        p2p_011_peerbook::PeerBook,
    },
    reorganization::reorg_006_manager::ReorgManager,
    runtime::{p2p_001_sync_builders::P2pSync, p2p_006_sync_runtime::NodeOpts},
    storage::rocksdb_005_manager::RockDBManager,
    utility::{
        alpha_001_global_configuration::GlobalConfiguration,
        alpha_003_detection_system::DetectionSystem,
    },
};
use std::{
    collections::BTreeSet,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type TestResult<T = ()> = Result<T, String>;

const DEFAULT_TEST_TIMEOUT: Duration = Duration::from_secs(8);
const SHORT_TEST_TIMEOUT: Duration = Duration::from_secs(4);

static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct SyncHarness {
    sync: P2pSync,
    data_dir: PathBuf,
}

fn fmt_err<E: std::fmt::Debug>(err: E) -> String {
    format!("{err:?}")
}

fn run_async<T, F>(future: F) -> TestResult<T>
where
    F: Future<Output = TestResult<T>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(fmt_err)?;

    runtime.block_on(future)
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
        "remzar_p2p_003_sync_swarmevent_tests_{}_{}_{}_{}",
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

fn test_peer_id() -> PeerId {
    let keypair = identity::Keypair::generate_ed25519();
    PeerId::from(keypair.public())
}

fn make_swarm() -> TestResult<Swarm<RemzarBehaviour>> {
    let keypair = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let transport = build_transport(keypair.clone()).map_err(fmt_err)?;
    let mut behaviour = RemzarBehaviour::new(keypair).map_err(fmt_err)?;

    behaviour
        .gossipsub
        .subscribe(&IdentTopic::new("remzar"))
        .map_err(fmt_err)?;

    Ok(Swarm::new(
        transport,
        behaviour,
        peer_id,
        SwarmConfig::with_tokio_executor(),
    ))
}

fn loopback_tcp_zero() -> TestResult<Multiaddr> {
    "/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().map_err(fmt_err)
}

fn closed_loopback_addr_with_peer(peer: &PeerId) -> TestResult<Multiaddr> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(fmt_err)?;
    let addr = listener.local_addr().map_err(fmt_err)?;
    let port = addr.port();
    drop(listener);

    format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
        .parse::<Multiaddr>()
        .map_err(fmt_err)
}

async fn next_listen_event(swarm: &mut Swarm<RemzarBehaviour>) -> TestResult<SwarmEvent<OutEvent>> {
    let _listener_id = swarm.listen_on(loopback_tcp_zero()?).map_err(fmt_err)?;

    let wait = async {
        loop {
            match swarm.select_next_some().await {
                event @ SwarmEvent::NewListenAddr { .. } => return Ok(event),
                SwarmEvent::IncomingConnectionError { error, .. } => {
                    return Err(format!(
                        "incoming connection failed while listening: {error:?}"
                    ));
                }
                _ => {}
            }
        }
    };

    tokio::time::timeout(DEFAULT_TEST_TIMEOUT, wait)
        .await
        .map_err(fmt_err)?
}

async fn drive_one_listen_event(
    sync: &mut P2pSync,
    swarm: &mut Swarm<RemzarBehaviour>,
) -> TestResult<Multiaddr> {
    let event = next_listen_event(swarm).await?;
    let observed = match &event {
        SwarmEvent::NewListenAddr { address, .. } => address.clone(),
        _ => return Err("expected NewListenAddr event".to_string()),
    };

    sync.on_swarm_event(event, swarm, None);
    Ok(observed)
}

async fn next_outgoing_error_event(
    swarm: &mut Swarm<RemzarBehaviour>,
    peer: &PeerId,
) -> TestResult<SwarmEvent<OutEvent>> {
    let addr = closed_loopback_addr_with_peer(peer)?;
    swarm.dial(addr).map_err(fmt_err)?;

    let wait = async {
        loop {
            match swarm.select_next_some().await {
                event @ SwarmEvent::OutgoingConnectionError { .. } => return Ok(event),
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    return Err(format!(
                        "closed-port dial unexpectedly connected to {peer_id}"
                    ));
                }
                _ => {}
            }
        }
    };

    tokio::time::timeout(SHORT_TEST_TIMEOUT, wait)
        .await
        .map_err(fmt_err)?
}

async fn drive_outgoing_error_event_for_peer(
    sync: &mut P2pSync,
    swarm: &mut Swarm<RemzarBehaviour>,
    peer: &PeerId,
) -> TestResult {
    let event = next_outgoing_error_event(swarm, peer).await?;

    match &event {
        SwarmEvent::OutgoingConnectionError {
            peer_id: Some(actual),
            ..
        } => {
            if actual != peer {
                return Err(format!(
                    "outgoing error peer mismatch: expected {peer}, got {actual}"
                ));
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id: None, .. } => {
            return Err("outgoing error did not include peer id".to_string());
        }
        _ => return Err("expected OutgoingConnectionError event".to_string()),
    }

    sync.on_swarm_event(event, swarm, None);
    Ok(())
}

fn tracked_block_work(sync: &P2pSync) -> usize {
    sync.block_queue
        .len()
        .saturating_add(sync.pending_blocks.len())
}

fn tracked_batch_work(sync: &P2pSync) -> usize {
    sync.batch_queue
        .len()
        .saturating_add(sync.pending_batches.len())
}

fn assert_initial_public_state(sync: &P2pSync) {
    assert!(!sync.has_synced());
    assert!(sync.is_syncing());
    assert_eq!(sync.total_to_download, 0u64);
    assert_eq!(sync.downloaded, 0u64);
    assert!(sync.pending_versions.is_empty());
    assert!(sync.pending_pq.is_empty());
    assert!(sync.pending_blocks.is_empty());
    assert!(sync.pending_batches.is_empty());
    assert!(sync.block_queue.is_empty());
    assert!(sync.batch_queue.is_empty());
    assert!(sync.pq_ready_peers.is_empty());
    assert!(sync.pq_initiators.is_empty());
    assert!(!sync.tried_genesis);
}

#[test]
fn p2p_01_003_sync_swarmevent_constructs_real_sync_and_swarm() -> TestResult {
    run_async(async {
        let harness = build_sync_harness("p2p_01")?;
        let swarm = make_swarm()?;

        assert_initial_public_state(&harness.sync);
        assert!(harness.data_dir.exists());
        assert!(!swarm.local_peer_id().to_string().is_empty());
        Ok(())
    })
}

#[test]
fn p2p_02_003_sync_swarmevent_new_listen_addr_event_is_handled() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_02")?;
        let mut swarm = make_swarm()?;

        let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(addr.to_string().starts_with("/ip4/127.0.0.1/tcp/"));
        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_03_003_sync_swarmevent_new_listen_addr_preserves_expected_genesis_hash() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_03")?;
        let mut swarm = make_swarm()?;

        let before = harness.sync.expected_genesis_hash.clone();
        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert_eq!(harness.sync.expected_genesis_hash, before);
        Ok(())
    })
}

#[test]
fn p2p_04_003_sync_swarmevent_new_listen_addr_preserves_download_counters() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_04")?;
        let mut swarm = make_swarm()?;

        harness.sync.total_to_download = 100u64;
        harness.sync.downloaded = 25u64;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        // With no active sync work queued or pending, swarm-event handling
        // reconciles visible counters back to the local DB tip.
        assert_eq!(harness.sync.total_to_download, 0u64);
        assert_eq!(harness.sync.downloaded, 0u64);
        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        Ok(())
    })
}

#[test]
fn p2p_05_003_sync_swarmevent_new_listen_addr_preserves_pq_ready_peer() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_05")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        harness.sync.mark_pq_ready(peer);
        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.is_pq_ready(&peer));
        assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
        Ok(())
    })
}

#[test]
fn p2p_06_003_sync_swarmevent_new_listen_addr_preserves_block_work() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_06")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        harness.sync.block_queue.push_back((peer, 6u64, 3u8));
        let before = tracked_block_work(&harness.sync);

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        let after = tracked_block_work(&harness.sync);

        assert_eq!(before, 1usize);
        assert_eq!(after, 1usize);
        assert!(harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_07_003_sync_swarmevent_new_listen_addr_preserves_batch_work() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_07")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        harness.sync.batch_queue.push_back((peer, 7u64, 2u8));
        let before = tracked_batch_work(&harness.sync);

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        let after = tracked_batch_work(&harness.sync);

        assert_eq!(before, 1usize);
        assert_eq!(after, 1usize);
        assert!(harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_08_003_sync_swarmevent_new_listen_addr_keeps_pending_maps_empty() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_08")?;
        let mut swarm = make_swarm()?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.pending_versions.is_empty());
        assert!(harness.sync.pending_pq.is_empty());
        assert!(harness.sync.pending_blocks.is_empty());
        assert!(harness.sync.pending_batches.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_09_003_sync_swarmevent_multiple_listen_events_have_unique_addresses() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_09")?;
        let mut swarm = make_swarm()?;
        let mut addrs = BTreeSet::new();

        for _ in 0usize..4usize {
            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let inserted = addrs.insert(addr.to_string());

            assert!(inserted);
        }

        assert_eq!(addrs.len(), 4usize);
        assert!(!harness.sync.has_synced());
        Ok(())
    })
}

#[test]
fn p2p_10_003_sync_swarmevent_vector_listen_events_preserve_sync_percent() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_10")?;
        let mut swarm = make_swarm()?;

        let cases = [
            (4u64, 0u64),
            (4u64, 1u64),
            (4u64, 2u64),
            (4u64, 3u64),
            (4u64, 4u64),
        ];

        for (total, downloaded) in cases {
            harness.sync.total_to_download = total;
            harness.sync.downloaded = downloaded;

            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

            assert_eq!(harness.sync.total_to_download, 0u64);
            assert_eq!(harness.sync.downloaded, 0u64);
            assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        }

        Ok(())
    })
}

#[test]
fn p2p_11_003_sync_swarmevent_outgoing_error_for_pq_peer_clears_pq_state() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_11")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        harness.sync.mark_pq_ready(peer);
        assert!(harness.sync.is_pq_ready(&peer));

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &peer).await?;

        assert!(!harness.sync.is_pq_ready(&peer));
        Ok(())
    })
}

#[test]
fn p2p_12_003_sync_swarmevent_outgoing_error_unknown_peer_preserves_ready_peer() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_12")?;
        let mut swarm = make_swarm()?;
        let ready_peer = test_peer_id();
        let failed_peer = test_peer_id();

        harness.sync.mark_pq_ready(ready_peer);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(harness.sync.is_pq_ready(&ready_peer));
        assert!(!harness.sync.is_pq_ready(&failed_peer));
        Ok(())
    })
}

#[test]
fn p2p_13_003_sync_swarmevent_outgoing_error_reconciles_downloaded_to_local_tip() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_13")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        harness.sync.total_to_download = 300u64;
        harness.sync.downloaded = 75u64;

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert_eq!(harness.sync.total_to_download, 300u64);
        assert_eq!(harness.sync.downloaded, 0u64);
        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        Ok(())
    })
}

#[test]
fn p2p_14_003_sync_swarmevent_outgoing_error_preserves_queued_or_pending_work_for_unrelated_peer()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_14")?;
        let mut swarm = make_swarm()?;
        let queue_peer = test_peer_id();
        let failed_peer = test_peer_id();

        harness.sync.block_queue.push_back((queue_peer, 14u64, 3u8));
        harness.sync.batch_queue.push_back((queue_peer, 14u64, 2u8));

        let block_before = tracked_block_work(&harness.sync);
        let batch_before = tracked_batch_work(&harness.sync);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert_eq!(tracked_block_work(&harness.sync), block_before);
        assert_eq!(tracked_batch_work(&harness.sync), batch_before);
        assert!(harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_15_003_sync_swarmevent_outgoing_error_keeps_pending_maps_empty() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_15")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(harness.sync.pending_versions.is_empty());
        assert!(harness.sync.pending_pq.is_empty());
        assert!(harness.sync.pending_blocks.is_empty());
        assert!(harness.sync.pending_batches.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_16_003_sync_swarmevent_outgoing_error_does_not_set_has_synced() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_16")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_17_003_sync_swarmevent_multiple_outgoing_errors_clear_matching_ready_peers() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_17")?;
        let mut swarm = make_swarm()?;
        let mut peers = Vec::new();

        for _ in 0usize..3usize {
            let peer = test_peer_id();
            harness.sync.mark_pq_ready(peer);
            peers.push(peer);
        }

        for peer in &peers {
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, peer).await?;
            assert!(!harness.sync.is_pq_ready(peer));
        }

        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_18_003_sync_swarmevent_vector_outgoing_errors_preserve_unfailed_ready_peers() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_18")?;
        let mut swarm = make_swarm()?;
        let keep_peer = test_peer_id();

        harness.sync.mark_pq_ready(keep_peer);

        for _ in 0usize..4usize {
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert!(harness.sync.is_pq_ready(&keep_peer));
        assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
        Ok(())
    })
}

#[test]
fn p2p_19_003_sync_swarmevent_listen_after_outgoing_error_still_handles_event() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_19")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;
        let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(addr.to_string().starts_with("/ip4/127.0.0.1/tcp/"));
        assert!(!harness.sync.has_synced());
        Ok(())
    })
}

#[test]
fn p2p_20_003_sync_swarmevent_outgoing_error_after_listen_still_clears_peer() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_20")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        harness.sync.mark_pq_ready(failed_peer);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(!harness.sync.is_pq_ready(&failed_peer));
        Ok(())
    })
}

#[test]
fn p2p_21_003_sync_swarmevent_load_twenty_listen_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_21")?;
        let mut swarm = make_swarm()?;
        let mut addrs = BTreeSet::new();

        for _ in 0usize..20usize {
            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            addrs.insert(addr.to_string());
        }

        assert_eq!(addrs.len(), 20usize);
        assert!(harness.sync.pending_blocks.is_empty());
        assert!(harness.sync.pending_batches.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_22_003_sync_swarmevent_load_ten_outgoing_errors() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_22")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..10usize {
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert!(harness.sync.pq_ready_peers.is_empty());
        assert!(!harness.sync.has_synced());
        Ok(())
    })
}

#[test]
fn p2p_23_003_sync_swarmevent_fuzz_listen_events_with_counter_vectors() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_23")?;
        let mut swarm = make_swarm()?;

        for downloaded in 0u64..=10u64 {
            harness.sync.total_to_download = 10u64;
            harness.sync.downloaded = downloaded;

            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

            assert_eq!(harness.sync.total_to_download, 0u64);
            assert_eq!(harness.sync.downloaded, 0u64);
            assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        }

        Ok(())
    })
}

#[test]
fn p2p_24_003_sync_swarmevent_fuzz_outgoing_errors_with_many_ready_peers() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_24")?;
        let mut swarm = make_swarm()?;
        let mut peers = Vec::new();

        for _ in 0usize..8usize {
            let peer = test_peer_id();
            harness.sync.mark_pq_ready(peer);
            peers.push(peer);
        }

        for peer in peers {
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &peer).await?;
        }

        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_25_003_sync_swarmevent_edge_outgoing_error_for_same_peer_twice_is_safe() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_25")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        harness.sync.mark_pq_ready(peer);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &peer).await?;
        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &peer).await?;

        assert!(!harness.sync.is_pq_ready(&peer));
        Ok(())
    })
}

#[test]
fn p2p_26_003_sync_swarmevent_edge_new_listen_does_not_clear_ready_set() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_26")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..16usize {
            harness.sync.mark_pq_ready(test_peer_id());
        }

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert_eq!(harness.sync.pq_ready_peers.len(), 16usize);
        Ok(())
    })
}

#[test]
fn p2p_27_003_sync_swarmevent_edge_new_listen_with_large_queues_keeps_work_bounded() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_27")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        for index in 0u64..128u64 {
            harness.sync.block_queue.push_back((peer, index, 3u8));
            harness.sync.batch_queue.push_back((peer, index, 2u8));
        }

        let block_before = tracked_block_work(&harness.sync);
        let batch_before = tracked_batch_work(&harness.sync);

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        let block_after = tracked_block_work(&harness.sync);
        let batch_after = tracked_batch_work(&harness.sync);

        assert_eq!(block_before, 128usize);
        assert_eq!(batch_before, 128usize);
        assert!(block_after <= block_before);
        assert!(batch_after <= batch_before);
        assert!(block_after >= 120usize);
        assert!(batch_after >= 120usize);
        assert!(harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_28_003_sync_swarmevent_edge_outgoing_error_with_large_queues_keeps_work_bounded()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_28")?;
        let mut swarm = make_swarm()?;
        let queue_peer = test_peer_id();
        let failed_peer = test_peer_id();

        for index in 0u64..128u64 {
            harness.sync.block_queue.push_back((queue_peer, index, 3u8));
            harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
        }

        let block_before = tracked_block_work(&harness.sync);
        let batch_before = tracked_batch_work(&harness.sync);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        let block_after = tracked_block_work(&harness.sync);
        let batch_after = tracked_batch_work(&harness.sync);

        assert_eq!(block_before, 128usize);
        assert_eq!(batch_before, 128usize);
        assert!(block_after <= block_before);
        assert!(batch_after <= batch_before);
        assert!(block_after >= 120usize);
        assert!(batch_after >= 120usize);
        assert!(harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_29_003_sync_swarmevent_edge_new_listen_preserves_tried_genesis_true() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_29")?;
        let mut swarm = make_swarm()?;

        harness.sync.tried_genesis = true;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.tried_genesis);
        Ok(())
    })
}

#[test]
fn p2p_30_003_sync_swarmevent_edge_outgoing_error_preserves_tried_genesis_true() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_30")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        harness.sync.tried_genesis = true;

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(harness.sync.tried_genesis);
        Ok(())
    })
}

#[test]
fn p2p_31_003_sync_swarmevent_property_listen_addr_roundtrips_through_string() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_31")?;
        let mut swarm = make_swarm()?;

        let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        let parsed = addr.to_string().parse::<Multiaddr>().map_err(fmt_err)?;

        assert_eq!(addr, parsed);
        Ok(())
    })
}

#[test]
fn p2p_32_003_sync_swarmevent_property_multiple_listen_addrs_roundtrip() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_32")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..8usize {
            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let parsed = addr.to_string().parse::<Multiaddr>().map_err(fmt_err)?;

            assert_eq!(addr, parsed);
        }

        Ok(())
    })
}

#[test]
fn p2p_33_003_sync_swarmevent_property_swarm_peer_id_stable_after_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_33")?;
        let mut swarm = make_swarm()?;
        let peer_before = *swarm.local_peer_id();

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        let failed_peer = test_peer_id();
        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert_eq!(*swarm.local_peer_id(), peer_before);
        Ok(())
    })
}

#[test]
fn p2p_34_003_sync_swarmevent_property_sync_state_stays_unsynced_without_genesis() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_34")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..4usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        }

        harness.sync.update_sync_state();

        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_35_003_sync_swarmevent_property_no_background_work_after_empty_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_35")?;
        let mut swarm = make_swarm()?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        let failed_peer = test_peer_id();
        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(!harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_36_003_sync_swarmevent_adversarial_outgoing_error_does_not_clear_other_many_ready_peers()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_36")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        for _ in 0usize..32usize {
            harness.sync.mark_pq_ready(test_peer_id());
        }

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert_eq!(harness.sync.pq_ready_peers.len(), 32usize);
        Ok(())
    })
}

#[test]
fn p2p_37_003_sync_swarmevent_adversarial_mixed_events_preserve_block_work_count() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_37")?;
        let mut swarm = make_swarm()?;
        let queue_peer = test_peer_id();

        for index in 0u64..10u64 {
            harness.sync.block_queue.push_back((queue_peer, index, 3u8));
        }

        let before = tracked_block_work(&harness.sync);

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        let failed_peer = test_peer_id();
        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert_eq!(tracked_block_work(&harness.sync), before);
        assert!(harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_38_003_sync_swarmevent_load_create_ten_swarms_and_handle_listen_event() -> TestResult {
    run_async(async {
        let mut handled = 0usize;

        for index in 0usize..10usize {
            let mut harness = build_sync_harness(&format!("p2p_38_{index}"))?;
            let mut swarm = make_swarm()?;

            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            assert!(addr.to_string().starts_with("/ip4/127.0.0.1/tcp/"));

            handled = handled
                .checked_add(1usize)
                .ok_or_else(|| "handled counter overflow".to_string())?;
        }

        assert_eq!(handled, 10usize);
        Ok(())
    })
}

#[test]
fn p2p_39_003_sync_swarmevent_load_create_ten_swarms_and_handle_outgoing_error() -> TestResult {
    run_async(async {
        let mut handled = 0usize;

        for index in 0usize..10usize {
            let mut harness = build_sync_harness(&format!("p2p_39_{index}"))?;
            let mut swarm = make_swarm()?;
            let failed_peer = test_peer_id();

            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;

            handled = handled
                .checked_add(1usize)
                .ok_or_else(|| "handled counter overflow".to_string())?;
        }

        assert_eq!(handled, 10usize);
        Ok(())
    })
}

#[test]
fn p2p_40_003_sync_swarmevent_end_to_end_event_stress_public_state_invariants() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_40")?;
        let mut swarm = make_swarm()?;
        let queue_peer = test_peer_id();

        harness.sync.total_to_download = 1_000u64;
        harness.sync.downloaded = 250u64;

        for index in 0u64..32u64 {
            harness.sync.block_queue.push_back((queue_peer, index, 3u8));
            harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
            harness.sync.mark_pq_ready(test_peer_id());
        }

        let block_before = tracked_block_work(&harness.sync);
        let batch_before = tracked_batch_work(&harness.sync);

        for _ in 0usize..2usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        }

        let block_after = tracked_block_work(&harness.sync);
        let batch_after = tracked_batch_work(&harness.sync);

        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
        assert!(block_after <= block_before);
        assert!(batch_after <= batch_before);
        assert!(block_after >= block_before.saturating_sub(2usize));
        assert!(batch_after >= batch_before.saturating_sub(2usize));
        assert_eq!(harness.sync.pq_ready_peers.len(), 32usize);
        assert!(harness.sync.has_background_sync_work());
        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_41_003_sync_swarmevent_listen_event_address_contains_tcp_protocol() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_41")?;
        let mut swarm = make_swarm()?;

        let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        let addr_text = addr.to_string();

        assert!(addr_text.contains("/tcp/"));
        assert!(addr_text.starts_with("/ip4/127.0.0.1/tcp/"));
        Ok(())
    })
}

#[test]
fn p2p_42_003_sync_swarmevent_listen_event_port_is_nonzero() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_42")?;
        let mut swarm = make_swarm()?;

        let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        let addr_text = addr.to_string();
        let port_text = addr_text
            .rsplit('/')
            .next()
            .ok_or_else(|| "listen addr missing tcp port".to_string())?;
        let port = port_text.parse::<u16>().map_err(fmt_err)?;

        assert_ne!(port, 0u16);
        Ok(())
    })
}

#[test]
fn p2p_43_003_sync_swarmevent_two_listen_events_produce_distinct_ports() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_43")?;
        let mut swarm = make_swarm()?;

        let first = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        let second = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert_ne!(first, second);
        Ok(())
    })
}

#[test]
fn p2p_44_003_sync_swarmevent_listen_event_keeps_db_tip_height_stable() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_44")?;
        let mut swarm = make_swarm()?;
        let before = harness.sync.db.get_tip_height().map_err(fmt_err)?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        let after = harness.sync.db.get_tip_height().map_err(fmt_err)?;
        assert_eq!(after, before);
        Ok(())
    })
}

#[test]
fn p2p_45_003_sync_swarmevent_listen_event_keeps_addr_index_height_stable() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_45")?;
        let mut swarm = make_swarm()?;
        let before = harness.sync.db.get_addr_index_height().map_err(fmt_err)?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        let after = harness.sync.db.get_addr_index_height().map_err(fmt_err)?;
        assert_eq!(after, before);
        Ok(())
    })
}

#[test]
fn p2p_46_003_sync_swarmevent_listen_event_keeps_chain_blocks_empty_without_blocks() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_46")?;
        let mut swarm = make_swarm()?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.chain.get_blocks().is_empty());
        Ok(())
    })
}

#[test]
fn p2p_47_003_sync_swarmevent_listen_event_keeps_chain_balances_empty_without_blocks() -> TestResult
{
    run_async(async {
        let mut harness = build_sync_harness("p2p_47")?;
        let mut swarm = make_swarm()?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.chain.get_balances().is_empty());
        Ok(())
    })
}

#[test]
fn p2p_48_003_sync_swarmevent_listen_event_keeps_last_synced_index_none_without_blocks()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_48")?;
        let mut swarm = make_swarm()?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.last_synced_index().is_none());
        Ok(())
    })
}

#[test]
fn p2p_49_003_sync_swarmevent_listen_event_keeps_last_synced_hash_none_without_blocks() -> TestResult
{
    run_async(async {
        let mut harness = build_sync_harness("p2p_49")?;
        let mut swarm = make_swarm()?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.last_synced_hash().is_none());
        Ok(())
    })
}

#[test]
fn p2p_50_003_sync_swarmevent_listen_event_preserves_empty_pending_requests() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_50")?;
        let mut swarm = make_swarm()?;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.pending_versions.is_empty());
        assert!(harness.sync.pending_pq.is_empty());
        assert!(harness.sync.pending_blocks.is_empty());
        assert!(harness.sync.pending_batches.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_51_003_sync_swarmevent_outgoing_error_for_ready_peer_is_idempotent() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_51")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        harness.sync.mark_pq_ready(peer);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &peer).await?;
        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &peer).await?;

        assert!(!harness.sync.is_pq_ready(&peer));
        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_52_003_sync_swarmevent_outgoing_error_for_unknown_peer_keeps_ready_set_empty() -> TestResult
{
    run_async(async {
        let mut harness = build_sync_harness("p2p_52")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(harness.sync.pq_ready_peers.is_empty());
        assert!(!harness.sync.is_pq_ready(&failed_peer));
        Ok(())
    })
}

#[test]
fn p2p_53_003_sync_swarmevent_outgoing_error_for_one_ready_peer_preserves_others() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_53")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();
        let kept_peer = test_peer_id();

        harness.sync.mark_pq_ready(failed_peer);
        harness.sync.mark_pq_ready(kept_peer);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(!harness.sync.is_pq_ready(&failed_peer));
        assert!(harness.sync.is_pq_ready(&kept_peer));
        assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
        Ok(())
    })
}

#[test]
fn p2p_54_003_sync_swarmevent_outgoing_error_vector_clears_each_failed_peer() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_54")?;
        let mut swarm = make_swarm()?;
        let mut peers = Vec::new();

        for _ in 0usize..6usize {
            let peer = test_peer_id();
            harness.sync.mark_pq_ready(peer);
            peers.push(peer);
        }

        for peer in &peers {
            assert!(harness.sync.is_pq_ready(peer));
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, peer).await?;
            assert!(!harness.sync.is_pq_ready(peer));
        }

        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_55_003_sync_swarmevent_outgoing_error_preserves_expected_genesis_hash() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_55")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();
        let before = harness.sync.expected_genesis_hash.clone();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert_eq!(harness.sync.expected_genesis_hash, before);
        Ok(())
    })
}

#[test]
fn p2p_56_003_sync_swarmevent_outgoing_error_keeps_db_tip_height_stable() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_56")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();
        let before = harness.sync.db.get_tip_height().map_err(fmt_err)?;

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        let after = harness.sync.db.get_tip_height().map_err(fmt_err)?;
        assert_eq!(after, before);
        Ok(())
    })
}

#[test]
fn p2p_57_003_sync_swarmevent_outgoing_error_keeps_addr_index_height_stable() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_57")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();
        let before = harness.sync.db.get_addr_index_height().map_err(fmt_err)?;

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        let after = harness.sync.db.get_addr_index_height().map_err(fmt_err)?;
        assert_eq!(after, before);
        Ok(())
    })
}

#[test]
fn p2p_58_003_sync_swarmevent_outgoing_error_keeps_chain_empty_without_blocks() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_58")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(harness.sync.chain.get_blocks().is_empty());
        assert!(harness.sync.chain.get_balances().is_empty());
        Ok(())
    })
}

#[test]
fn p2p_59_003_sync_swarmevent_outgoing_error_keeps_last_synced_pointers_none() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_59")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(harness.sync.last_synced_index().is_none());
        assert!(harness.sync.last_synced_hash().is_none());
        Ok(())
    })
}

#[test]
fn p2p_60_003_sync_swarmevent_outgoing_error_preserves_empty_pending_maps() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_60")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(harness.sync.pending_versions.is_empty());
        assert!(harness.sync.pending_pq.is_empty());
        assert!(harness.sync.pending_blocks.is_empty());
        assert!(harness.sync.pending_batches.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_61_003_sync_swarmevent_vector_listen_then_outgoing_error_preserves_percent_cases()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_61")?;
        let mut swarm = make_swarm()?;

        let cases = [
            (100u64, 0u64),
            (100u64, 25u64),
            (100u64, 50u64),
            (100u64, 75u64),
            (100u64, 100u64),
            (100u64, 125u64),
        ];

        for (total, downloaded) in cases {
            harness.sync.total_to_download = total;
            harness.sync.downloaded = downloaded;

            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;

            assert_eq!(harness.sync.total_to_download, 0u64);
            assert_eq!(harness.sync.downloaded, 0u64);
            assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        }

        Ok(())
    })
}

#[test]
fn p2p_62_003_sync_swarmevent_vector_many_listen_events_keep_unique_roundtrips() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_62")?;
        let mut swarm = make_swarm()?;
        let mut addrs = BTreeSet::new();

        for _ in 0usize..12usize {
            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let parsed = addr.to_string().parse::<Multiaddr>().map_err(fmt_err)?;

            assert_eq!(addr, parsed);
            assert!(addrs.insert(addr.to_string()));
        }

        assert_eq!(addrs.len(), 12usize);
        Ok(())
    })
}

#[test]
fn p2p_63_003_sync_swarmevent_vector_outgoing_errors_with_ready_and_unready_peers() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_63")?;
        let mut swarm = make_swarm()?;
        let survivor = test_peer_id();

        harness.sync.mark_pq_ready(survivor);

        for _ in 0usize..10usize {
            let unready_failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(
                &mut harness.sync,
                &mut swarm,
                &unready_failed_peer,
            )
            .await?;
        }

        assert!(harness.sync.is_pq_ready(&survivor));
        assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
        Ok(())
    })
}

#[test]
fn p2p_64_003_sync_swarmevent_unknown_event_keeps_mixed_work_bounded() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_64")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        for index in 0u64..128u64 {
            harness.sync.block_queue.push_back((peer, index, 3u8));
            harness.sync.batch_queue.push_back((peer, index, 2u8));
        }

        let block_before = tracked_block_work(&harness.sync);
        let batch_before = tracked_batch_work(&harness.sync);

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        let block_after = tracked_block_work(&harness.sync);
        let batch_after = tracked_batch_work(&harness.sync);

        assert!(block_after <= block_before);
        assert!(batch_after <= batch_before);
        assert!(block_after >= block_before.saturating_sub(1usize));
        assert!(batch_after >= batch_before.saturating_sub(1usize));
        assert!(harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_65_003_sync_swarmevent_edge_manual_has_synced_true_reset_by_outgoing_error_without_genesis()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_65")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        harness.sync.has_synced = true;

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_66_003_sync_swarmevent_edge_total_zero_unsynced_percent_remains_zero_after_event()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_66")?;
        let mut swarm = make_swarm()?;

        harness.sync.has_synced = false;
        harness.sync.total_to_download = 0u64;
        harness.sync.downloaded = 99u64;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        Ok(())
    })
}

#[test]
fn p2p_67_003_sync_swarmevent_edge_overdownloaded_reconciles_after_outgoing_error() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_67")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        harness.sync.total_to_download = 3u64;
        harness.sync.downloaded = 10u64;

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert_eq!(harness.sync.total_to_download, 3u64);
        assert_eq!(harness.sync.downloaded, 0u64);
        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        Ok(())
    })
}

#[test]
fn p2p_68_003_sync_swarmevent_edge_zero_download_large_total_after_listen() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_68")?;
        let mut swarm = make_swarm()?;

        harness.sync.total_to_download = u64::MAX / 10_000u64;
        harness.sync.downloaded = 0u64;

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        Ok(())
    })
}

#[test]
fn p2p_69_003_sync_swarmevent_edge_full_download_large_safe_total_reconciles_after_outgoing_error()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_69")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        let safe_total = u64::MAX / 10_000u64;
        harness.sync.total_to_download = safe_total;
        harness.sync.downloaded = safe_total;

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert_eq!(harness.sync.total_to_download, safe_total);
        assert_eq!(harness.sync.downloaded, 0u64);
        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        Ok(())
    })
}

#[test]
fn p2p_70_003_sync_swarmevent_property_local_peer_id_stable_after_many_listen_events() -> TestResult
{
    run_async(async {
        let mut harness = build_sync_harness("p2p_70")?;
        let mut swarm = make_swarm()?;
        let peer_before = *swarm.local_peer_id();

        for _ in 0usize..10usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        }

        assert_eq!(*swarm.local_peer_id(), peer_before);
        Ok(())
    })
}

#[test]
fn p2p_71_003_sync_swarmevent_property_local_peer_id_stable_after_many_outgoing_errors()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_71")?;
        let mut swarm = make_swarm()?;
        let peer_before = *swarm.local_peer_id();

        for _ in 0usize..10usize {
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert_eq!(*swarm.local_peer_id(), peer_before);
        Ok(())
    })
}

#[test]
fn p2p_72_003_sync_swarmevent_property_arc_db_count_stable_after_listen_event() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_72")?;
        let mut swarm = make_swarm()?;
        let before = Arc::strong_count(&harness.sync.db);

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        let after = Arc::strong_count(&harness.sync.db);
        assert_eq!(after, before);
        assert!(after >= 1usize);
        Ok(())
    })
}

#[test]
fn p2p_73_003_sync_swarmevent_property_arc_db_count_stable_after_outgoing_error() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_73")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();
        let before = Arc::strong_count(&harness.sync.db);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        let after = Arc::strong_count(&harness.sync.db);
        assert_eq!(after, before);
        assert!(after >= 1usize);
        Ok(())
    })
}

#[test]
fn p2p_74_003_sync_swarmevent_property_arc_mempool_count_stable_after_listen_event() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_74")?;
        let mut swarm = make_swarm()?;
        let before = Arc::strong_count(&harness.sync.mempool);

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        let after = Arc::strong_count(&harness.sync.mempool);
        assert_eq!(after, before);
        assert!(after >= 1usize);
        Ok(())
    })
}

#[test]
fn p2p_75_003_sync_swarmevent_property_arc_mempool_count_stable_after_outgoing_error() -> TestResult
{
    run_async(async {
        let mut harness = build_sync_harness("p2p_75")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();
        let before = Arc::strong_count(&harness.sync.mempool);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        let after = Arc::strong_count(&harness.sync.mempool);
        assert_eq!(after, before);
        assert!(after >= 1usize);
        Ok(())
    })
}

#[test]
fn p2p_76_003_sync_swarmevent_adversarial_alternating_listen_and_outgoing_error_events()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_76")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..6usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        assert!(harness.sync.pending_versions.is_empty());
        assert!(harness.sync.pending_pq.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_77_003_sync_swarmevent_adversarial_many_failed_ready_peers_then_listen() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_77")?;
        let mut swarm = make_swarm()?;
        let mut peers = Vec::new();

        for _ in 0usize..12usize {
            let peer = test_peer_id();
            harness.sync.mark_pq_ready(peer);
            peers.push(peer);
        }

        for peer in &peers {
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, peer).await?;
        }

        let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(addr.to_string().starts_with("/ip4/127.0.0.1/tcp/"));
        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_78_003_sync_swarmevent_adversarial_listen_events_do_not_poison_new_swarm() -> TestResult {
    run_async(async {
        {
            let mut harness = build_sync_harness("p2p_78_first")?;
            let mut swarm = make_swarm()?;

            for _ in 0usize..4usize {
                let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            }
        }

        let mut harness = build_sync_harness("p2p_78_second")?;
        let mut swarm = make_swarm()?;
        let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(addr.to_string().starts_with("/ip4/127.0.0.1/tcp/"));
        Ok(())
    })
}

#[test]
fn p2p_79_003_sync_swarmevent_adversarial_outgoing_errors_do_not_poison_new_swarm() -> TestResult {
    run_async(async {
        {
            let mut harness = build_sync_harness("p2p_79_first")?;
            let mut swarm = make_swarm()?;

            for _ in 0usize..4usize {
                let failed_peer = test_peer_id();
                drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                    .await?;
            }
        }

        let mut harness = build_sync_harness("p2p_79_second")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;
        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_80_003_sync_swarmevent_load_thirty_listen_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_80")?;
        let mut swarm = make_swarm()?;
        let mut addrs = BTreeSet::new();

        for _ in 0usize..30usize {
            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            addrs.insert(addr.to_string());
        }

        assert_eq!(addrs.len(), 30usize);
        assert!(!harness.sync.has_synced());
        Ok(())
    })
}

#[test]
fn p2p_81_003_sync_swarmevent_load_twenty_outgoing_error_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_81")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..20usize {
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert!(harness.sync.pq_ready_peers.is_empty());
        assert!(!harness.sync.has_synced());
        Ok(())
    })
}

#[test]
fn p2p_82_003_sync_swarmevent_load_unknown_forks_with_background_work() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_82")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        for index in 0u64..64u64 {
            harness.sync.block_queue.push_back((peer, index, 3u8));
        }

        let before = tracked_block_work(&harness.sync);

        for _ in 0usize..4usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        }

        assert_eq!(tracked_block_work(&harness.sync), before);
        assert!(harness.sync.has_background_sync_work());
        Ok(())
    })
}

#[test]
fn p2p_83_003_sync_swarmevent_load_create_twenty_swarms_and_outgoing_error_once() -> TestResult {
    run_async(async {
        let mut handled = 0usize;

        for index in 0usize..20usize {
            let mut harness = build_sync_harness(&format!("p2p_83_{index}"))?;
            let mut swarm = make_swarm()?;
            let failed_peer = test_peer_id();

            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;

            handled = handled
                .checked_add(1usize)
                .ok_or_else(|| "outgoing error swarm counter overflow".to_string())?;
        }

        assert_eq!(handled, 20usize);
        Ok(())
    })
}

#[test]
fn p2p_84_003_sync_swarmevent_load_ready_peer_churn_with_outgoing_errors() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_84")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..25usize {
            let peer = test_peer_id();
            harness.sync.mark_pq_ready(peer);
            assert!(harness.sync.is_pq_ready(&peer));

            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &peer).await?;
            assert!(!harness.sync.is_pq_ready(&peer));
        }

        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_85_003_sync_swarmevent_load_keep_one_ready_peer_through_many_other_errors() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_85")?;
        let mut swarm = make_swarm()?;
        let survivor = test_peer_id();

        harness.sync.mark_pq_ready(survivor);

        for _ in 0usize..25usize {
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert!(harness.sync.is_pq_ready(&survivor));
        assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
        Ok(())
    })
}

#[test]
fn p2p_86_003_sync_swarmevent_fuzz_percent_vectors_across_listen_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_86")?;
        let mut swarm = make_swarm()?;

        for total in 1u64..=12u64 {
            for downloaded in 0u64..=total.saturating_add(1u64) {
                harness.sync.total_to_download = total;
                harness.sync.downloaded = downloaded;

                let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

                let percent = harness.sync.sync_percent();
                assert!(percent >= 0.0);
                assert!(percent <= 100.0);
            }
        }

        Ok(())
    })
}

#[test]
fn p2p_87_003_sync_swarmevent_fuzz_percent_vectors_across_fast_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_87")?;
        let mut swarm = make_swarm()?;
        let mut checked = 0usize;

        for total in 1u64..=12u64 {
            for downloaded in 0u64..=total.saturating_add(1u64) {
                harness.sync.total_to_download = total;
                harness.sync.downloaded = downloaded;

                let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

                let percent = harness.sync.sync_percent();
                assert!(percent >= 0.0);
                assert!(percent <= 100.0);

                checked = checked
                    .checked_add(1usize)
                    .ok_or_else(|| "percent fuzz counter overflow".to_string())?;
            }
        }

        assert!(checked > 80usize);
        Ok(())
    })
}

#[test]
fn p2p_88_003_sync_swarmevent_many_events_keep_can_issue_pq_requests_true_when_no_pending_pq()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_88")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..5usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;

            assert!(harness.sync.can_issue_more_pq_requests());
        }

        Ok(())
    })
}

#[test]
fn p2p_89_003_sync_swarmevent_many_events_keep_pending_request_maps_empty() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_89")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..6usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert!(harness.sync.pending_versions.is_empty());
        assert!(harness.sync.pending_pq.is_empty());
        assert!(harness.sync.pending_blocks.is_empty());
        assert!(harness.sync.pending_batches.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_90_003_sync_swarmevent_many_events_keep_chain_db_empty_without_blocks() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_90")?;
        let mut swarm = make_swarm()?;

        for _ in 0usize..6usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert!(harness.sync.chain.get_blocks().is_empty());
        assert!(harness.sync.chain.get_balances().is_empty());
        assert_eq!(harness.sync.db.get_tip_height().map_err(fmt_err)?, 0u64);
        Ok(())
    })
}

#[test]
fn p2p_91_003_sync_swarmevent_listen_event_after_pq_clear_keeps_set_empty() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_91")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        harness.sync.mark_pq_ready(peer);
        harness.sync.clear_pq_peer_state(&peer);

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_92_003_sync_swarmevent_outgoing_error_after_manual_clear_keeps_set_empty() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_92")?;
        let mut swarm = make_swarm()?;
        let peer = test_peer_id();

        harness.sync.mark_pq_ready(peer);
        harness.sync.clear_pq_peer_state(&peer);

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &peer).await?;

        assert!(harness.sync.pq_ready_peers.is_empty());
        Ok(())
    })
}

#[test]
fn p2p_93_003_sync_swarmevent_listen_event_after_update_sync_pointers_keeps_none_without_blocks()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_93")?;
        let mut swarm = make_swarm()?;

        harness.sync.update_sync_pointers();

        let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;

        assert!(harness.sync.last_synced_index().is_none());
        assert!(harness.sync.last_synced_hash().is_none());
        Ok(())
    })
}

#[test]
fn p2p_94_003_sync_swarmevent_outgoing_error_after_update_sync_pointers_keeps_none_without_blocks()
-> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_94")?;
        let mut swarm = make_swarm()?;
        let failed_peer = test_peer_id();

        harness.sync.update_sync_pointers();

        drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer).await?;

        assert!(harness.sync.last_synced_index().is_none());
        assert!(harness.sync.last_synced_hash().is_none());
        Ok(())
    })
}

#[test]
fn p2p_95_003_sync_swarmevent_stress_15_listens_then_15_errors() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_95")?;
        let mut swarm = make_swarm()?;
        let mut addrs = BTreeSet::new();

        for _ in 0usize..15usize {
            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            addrs.insert(addr.to_string());
        }

        for _ in 0usize..15usize {
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert_eq!(addrs.len(), 15usize);
        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_96_003_sync_swarmevent_stress_15_errors_then_15_listens() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_96")?;
        let mut swarm = make_swarm()?;
        let mut addrs = BTreeSet::new();

        for _ in 0usize..15usize {
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        for _ in 0usize..15usize {
            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            addrs.insert(addr.to_string());
        }

        assert_eq!(addrs.len(), 15usize);
        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_97_003_sync_swarmevent_stress_ready_set_survives_unrelated_event_mix() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_97")?;
        let mut swarm = make_swarm()?;
        let survivor = test_peer_id();

        harness.sync.mark_pq_ready(survivor);

        for _ in 0usize..8usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert!(harness.sync.is_pq_ready(&survivor));
        assert_eq!(harness.sync.pq_ready_peers.len(), 1usize);
        Ok(())
    })
}

#[test]
fn p2p_98_003_sync_swarmevent_final_vector_state_after_mixed_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_98")?;
        let mut swarm = make_swarm()?;

        harness.sync.total_to_download = 600u64;
        harness.sync.downloaded = 150u64;
        harness.sync.tried_genesis = true;

        let survivor = test_peer_id();
        let queue_peer = test_peer_id();
        harness.sync.mark_pq_ready(survivor);

        for index in 0u64..16u64 {
            harness.sync.block_queue.push_back((queue_peer, index, 3u8));
            harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
        }

        let block_before = tracked_block_work(&harness.sync);
        let batch_before = tracked_batch_work(&harness.sync);

        for _ in 0usize..2usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
        }

        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "25.00");
        assert!(harness.sync.tried_genesis);
        assert!(harness.sync.is_pq_ready(&survivor));

        let block_after = tracked_block_work(&harness.sync);
        let batch_after = tracked_batch_work(&harness.sync);

        assert!(block_after <= block_before);
        assert!(batch_after <= batch_before);
        assert!(block_after > 0usize || batch_after > 0usize);
        assert!(harness.sync.has_background_sync_work());

        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_99_003_sync_swarmevent_final_vector_state_after_mixed_events() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_99")?;
        let mut swarm = make_swarm()?;

        harness.sync.total_to_download = 600u64;
        harness.sync.downloaded = 150u64;
        harness.sync.tried_genesis = true;

        let survivor = test_peer_id();
        harness.sync.mark_pq_ready(survivor);

        for _ in 0usize..5usize {
            let _addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            let failed_peer = test_peer_id();
            drive_outgoing_error_event_for_peer(&mut harness.sync, &mut swarm, &failed_peer)
                .await?;
        }

        assert_eq!(harness.sync.total_to_download, 0u64);
        assert_eq!(harness.sync.downloaded, 0u64);
        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "0.00");
        assert!(harness.sync.tried_genesis);
        assert!(harness.sync.is_pq_ready(&survivor));
        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}

#[test]
fn p2p_100_003_sync_swarmevent_final_public_event_stress_invariants() -> TestResult {
    run_async(async {
        let mut harness = build_sync_harness("p2p_100")?;
        let mut swarm = make_swarm()?;
        let local_peer_before = *swarm.local_peer_id();
        let queue_peer = test_peer_id();

        harness.sync.total_to_download = 1_000u64;
        harness.sync.downloaded = 500u64;

        let survivor = test_peer_id();
        harness.sync.mark_pq_ready(survivor);

        for index in 0u64..24u64 {
            harness.sync.block_queue.push_back((queue_peer, index, 3u8));
            harness.sync.batch_queue.push_back((queue_peer, index, 2u8));
        }

        let block_before = tracked_block_work(&harness.sync);
        let batch_before = tracked_batch_work(&harness.sync);
        let mut listen_addrs = BTreeSet::new();

        for _ in 0usize..3usize {
            let addr = drive_one_listen_event(&mut harness.sync, &mut swarm).await?;
            listen_addrs.insert(addr.to_string());
        }

        assert_eq!(*swarm.local_peer_id(), local_peer_before);
        assert_eq!(listen_addrs.len(), 3usize);
        assert_eq!(format!("{:.2}", harness.sync.sync_percent()), "50.00");
        assert!(harness.sync.is_pq_ready(&survivor));

        let block_after = tracked_block_work(&harness.sync);
        let batch_after = tracked_batch_work(&harness.sync);

        assert!(block_after <= block_before);
        assert!(batch_after <= batch_before);
        assert!(block_after > 0usize || batch_after > 0usize);
        assert!(harness.sync.has_background_sync_work());

        assert!(harness.sync.chain.get_blocks().is_empty());
        assert!(harness.sync.chain.get_balances().is_empty());
        assert!(!harness.sync.has_synced());
        assert!(harness.sync.is_syncing());
        Ok(())
    })
}
